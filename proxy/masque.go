package proxy

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	http "github.com/sardanioss/http"
	tls "github.com/sardanioss/utls"

	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
)

const (
	requestProtocol            = "connect-udp"
	capsuleProtocolHeaderValue = "?1"
	defaultInitialPacketSize   = 1350
)

type MASQUEConn struct {
	quicConn *quic.Conn

	clientConn *http3.ClientConn

	requestStream *http3.RequestStream

	targetHost string
	targetPort int

	resolvedTarget *net.UDPAddr

	mu          sync.RWMutex
	established bool
	closed      bool

	readDeadline  time.Time
	writeDeadline time.Time

	proxyHost string
	proxyPort string
	username  string
	password  string

	localAddr net.Addr

	datagramCh chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewMASQUEConn(proxyURL string) (*MASQUEConn, error) {
	normalizedURL, err := NormalizeMASQUEURL(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	parsed, err := url.Parse(normalizedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443" // Default HTTPS port
	}

	conn := &MASQUEConn{
		proxyHost:  host,
		proxyPort:  port,
		datagramCh: make(chan []byte, 100),
	}

	if parsed.User != nil {
		conn.username = parsed.User.Username()
		conn.password, _ = parsed.User.Password()
	}

	conn.localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

	return conn, nil
}

func (c *MASQUEConn) EstablishWithQUICConfig(ctx context.Context, targetHost string, targetPort int, tlsConfig *tls.Config, quicConfig *quic.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.established {
		return nil
	}

	if c.closed {
		return net.ErrClosed
	}

	c.targetHost = targetHost
	c.targetPort = targetPort

	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, c.proxyHost)
	if err != nil {
		return fmt.Errorf("failed to resolve proxy host %s: %w", c.proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return fmt.Errorf("no IP addresses found for proxy host %s", c.proxyHost)
	}

	port, err := strconv.Atoi(c.proxyPort)
	if err != nil {
		return fmt.Errorf("invalid proxy port %s: %w", c.proxyPort, err)
	}

	proxyIP := net.ParseIP(proxyIPs[0])
	proxyUDPAddr := &net.UDPAddr{IP: proxyIP, Port: port}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}

	proxyTLSConfig := tlsConfig.Clone()
	proxyTLSConfig.ServerName = c.proxyHost
	proxyTLSConfig.NextProtos = []string{http3.NextProtoH3}

	proxyCfg := quicConfig.Clone()
	proxyCfg.EnableDatagrams = true
	if proxyCfg.InitialPacketSize == 0 {
		proxyCfg.InitialPacketSize = defaultInitialPacketSize
	}

	quicConn, err := quic.Dial(ctx, udpConn, proxyUDPAddr, proxyTLSConfig, proxyCfg)
	if err != nil {
		return fmt.Errorf("failed to dial QUIC to proxy: %w", err)
	}
	c.quicConn = quicConn

	tr := &http3.Transport{EnableDatagrams: true}
	c.clientConn = tr.NewClientConn(quicConn)

	select {
	case <-ctx.Done():
		c.quicConn.CloseWithError(0, "context cancelled")
		return ctx.Err()
	case <-c.clientConn.Context().Done():
		return fmt.Errorf("connection closed: %w", c.clientConn.Context().Err())
	case <-c.clientConn.ReceivedSettings():
	}

	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect {
		c.quicConn.CloseWithError(0, "no extended connect")
		return errors.New("proxy doesn't support Extended CONNECT")
	}
	if !settings.EnableDatagrams {
		c.quicConn.CloseWithError(0, "no datagrams")
		return errors.New("proxy doesn't support HTTP/3 Datagrams")
	}

	if err := c.sendConnectUDP(ctx); err != nil {
		c.quicConn.CloseWithError(0, "connect-udp failed")
		return fmt.Errorf("CONNECT-UDP request failed: %w", err)
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	go c.receiveDatagrams()

	c.established = true
	return nil
}

func (c *MASQUEConn) Establish(ctx context.Context, targetHost string, targetPort int) error {
	tlsConfig := &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:    30 * time.Second,
		EnableDatagrams:   true,
		InitialPacketSize: defaultInitialPacketSize,
	}

	return c.EstablishWithQUICConfig(ctx, targetHost, targetPort, tlsConfig, quicConfig)
}

func (c *MASQUEConn) sendConnectUDP(ctx context.Context) error {
	rstr, err := c.clientConn.OpenRequestStream(ctx)
	if err != nil {
		return fmt.Errorf("failed to open request stream: %w", err)
	}
	c.requestStream = rstr

	path := fmt.Sprintf("/.well-known/masque/udp/%s/%d/", c.targetHost, c.targetPort)
	reqURL, _ := url.Parse(fmt.Sprintf("https://%s:%s%s", c.proxyHost, c.proxyPort, path))

	headers := http.Header{
		http3.CapsuleProtocolHeader: []string{capsuleProtocolHeaderValue},
	}

	if c.username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
		headers.Set("Proxy-Authorization", "Basic "+auth)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  requestProtocol, // This becomes :protocol = connect-udp
		Host:   reqURL.Host,
		Header: headers,
		URL:    reqURL,
	}

	if err := rstr.SendRequestHeader(req); err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	rsp, err := rstr.ReadResponse()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		switch rsp.StatusCode {
		case 407:
			return errors.New("proxy authentication required")
		case 403:
			return errors.New("proxy connection forbidden")
		case 502, 503:
			return errors.New("proxy could not reach target")
		default:
			return fmt.Errorf("proxy responded with %d", rsp.StatusCode)
		}
	}

	if rsp.Header.Get("X-Brd-Ip") != "" {
		c.localAddr = &net.UDPAddr{IP: net.ParseIP(rsp.Header.Get("X-Brd-Ip")), Port: 0}
	}

	return nil
}

func (c *MASQUEConn) receiveDatagrams() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		data, err := c.requestStream.ReceiveDatagram(c.ctx)
		if err != nil {
			return
		}

		payload := c.unwrapDatagram(data)
		if payload == nil {
			continue
		}

		select {
		case c.datagramCh <- payload:
		default:
		}
	}
}

func (c *MASQUEConn) unwrapDatagram(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	contextID, bytesRead := readVarInt(data)
	if bytesRead == 0 || bytesRead >= len(data) {
		return nil
	}

	if contextID != 0 {
		return nil
	}

	return data[bytesRead:]
}

func (c *MASQUEConn) wrapDatagram(data []byte) []byte {
	result := make([]byte, 1+len(data))
	result[0] = 0x00 // Context ID 0
	copy(result[1:], data)
	return result
}

func (c *MASQUEConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, errors.New("MASQUE connection not established")
	}
	rstr := c.requestStream
	c.mu.RUnlock()

	wrappedData := c.wrapDatagram(b)

	err := rstr.SendDatagram(wrappedData)
	if err != nil {
		return 0, fmt.Errorf("failed to send datagram: %w", err)
	}

	return len(b), nil
}

func (c *MASQUEConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, nil, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, nil, errors.New("MASQUE connection not established")
	}
	c.mu.RUnlock()

	var deadline <-chan time.Time
	c.mu.RLock()
	if !c.readDeadline.IsZero() {
		timer := time.NewTimer(time.Until(c.readDeadline))
		defer timer.Stop()
		deadline = timer.C
	}
	c.mu.RUnlock()

	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-deadline:
		return 0, nil, &net.OpError{Op: "read", Err: errors.New("i/o timeout")}
	case data := <-c.datagramCh:
		n := copy(b, data)
		c.mu.RLock()
		targetAddr := c.resolvedTarget
		c.mu.RUnlock()
		if targetAddr == nil {
			targetAddr = &net.UDPAddr{
				IP:   net.ParseIP(c.targetHost),
				Port: c.targetPort,
			}
			if targetAddr.IP == nil {
				targetAddr.IP = net.IPv4zero
			}
		}
		return n, targetAddr, nil
	}
}

func (c *MASQUEConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	if c.cancel != nil {
		c.cancel()
	}

	var errs []error

	if c.requestStream != nil {
		if err := c.requestStream.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.quicConn != nil {
		if err := c.quicConn.CloseWithError(0, "closed"); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (c *MASQUEConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *MASQUEConn) SetResolvedTarget(addr *net.UDPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resolvedTarget = addr
}

func (c *MASQUEConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *MASQUEConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *MASQUEConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

func readVarInt(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	prefix := data[0] >> 6
	length := 1 << prefix // 1, 2, 4, or 8 bytes

	if len(data) < length {
		return 0, 0
	}

	var value uint64
	switch length {
	case 1:
		value = uint64(data[0] & 0x3f)
	case 2:
		value = uint64(data[0]&0x3f)<<8 | uint64(data[1])
	case 4:
		value = uint64(data[0]&0x3f)<<24 | uint64(data[1])<<16 | uint64(data[2])<<8 | uint64(data[3])
	case 8:
		value = uint64(data[0]&0x3f)<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
			uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
	}

	return value, length
}

func writeVarInt(value uint64) []byte {
	if value <= 63 {
		return []byte{byte(value)}
	}
	if value <= 16383 {
		buf := make([]byte, 2)
		buf[0] = byte(value>>8) | 0x40
		buf[1] = byte(value)
		return buf
	}
	if value <= 1073741823 {
		buf := make([]byte, 4)
		buf[0] = byte(value>>24) | 0x80
		buf[1] = byte(value >> 16)
		buf[2] = byte(value >> 8)
		buf[3] = byte(value)
		return buf
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value|0xC000000000000000)
	return buf
}

func ParseMASQUETarget(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
