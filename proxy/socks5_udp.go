package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"
)

const (
	socks5Version = 0x05

	authNone     = 0x00
	authPassword = 0x02
	authNoAccept = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	replySuccess          = 0x00
	replyGeneralFailure   = 0x01
	replyConnNotAllowed   = 0x02
	replyNetworkUnreach   = 0x03
	replyHostUnreach      = 0x04
	replyConnRefused      = 0x05
	replyTTLExpired       = 0x06
	replyCmdNotSupported  = 0x07
	replyAddrNotSupported = 0x08
)

type SOCKS5UDPConn struct {
	tcpConn net.Conn

	udpConn *net.UDPConn

	relayAddr *net.UDPAddr

	proxyHost string
	proxyPort string

	username string
	password string

	mu           sync.RWMutex
	established  bool
	closed       bool
	lastActivity time.Time
	writeCount   int64
	readCount    int64

	readMu  sync.Mutex
	readBuf []byte

	readDeadline  time.Time
	writeDeadline time.Time
}

func NewSOCKS5UDPConn(proxyURL string) (*SOCKS5UDPConn, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy scheme: %s (need socks5)", parsed.Scheme)
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "1080" // Default SOCKS5 port
	}

	conn := &SOCKS5UDPConn{
		proxyHost: host,
		proxyPort: port,
		readBuf:   make([]byte, 65535), // Max UDP datagram size
	}

	if parsed.User != nil {
		conn.username = parsed.User.Username()
		conn.password, _ = parsed.User.Password()
	}

	return conn, nil
}

func (c *SOCKS5UDPConn) Establish(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.established {
		return nil
	}

	if c.closed {
		return net.ErrClosed
	}

	var lastErr error
	maxRetries := 5

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := c.tryEstablish(ctx)
		if err == nil {
			c.established = true
			c.lastActivity = time.Now()

			go c.tcpKeepalive()

			return nil
		}

		lastErr = err

		if c.udpConn != nil {
			c.udpConn.Close()
			c.udpConn = nil
		}
		if c.tcpConn != nil {
			c.tcpConn.Close()
			c.tcpConn = nil
		}

		if !isRetryableError(err) {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if attempt < maxRetries {
			time.Sleep(500 * time.Millisecond)
		}
	}

	return fmt.Errorf("UDP ASSOCIATE failed after %d attempts: %w", maxRetries, lastErr)
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), "reply=1") || contains(err.Error(), "general")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (c *SOCKS5UDPConn) tryEstablish(ctx context.Context) error {
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, c.proxyHost)
	if err != nil {
		return fmt.Errorf("failed to resolve proxy host %s: %w", c.proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return fmt.Errorf("no IP addresses found for proxy host %s", c.proxyHost)
	}

	proxyAddr := net.JoinHostPort(proxyIPs[0], c.proxyPort)
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}
	c.tcpConn = tcpConn

	deadline, ok := ctx.Deadline()
	if ok {
		c.tcpConn.SetDeadline(deadline)
	}

	if err := c.socks5Handshake(); err != nil {
		return fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %w", err)
	}
	c.udpConn = udpConn

	if err := c.sendUDPAssociate(); err != nil {
		return err
	}

	c.tcpConn.SetDeadline(time.Time{})

	if tcpConn, ok := c.tcpConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(15 * time.Second)
	}

	return nil
}

func (c *SOCKS5UDPConn) socks5Handshake() error {
	var greeting []byte
	if c.username != "" {
		greeting = []byte{socks5Version, 0x02, authNone, authPassword}
	} else {
		greeting = []byte{socks5Version, 0x01, authNone}
	}

	if _, err := c.tcpConn.Write(greeting); err != nil {
		return fmt.Errorf("failed to send greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version: %d", resp[0])
	}

	switch resp[1] {
	case authNone:
		return nil
	case authPassword:
		return c.socks5PasswordAuth()
	case authNoAccept:
		return errors.New("proxy rejected all authentication methods")
	default:
		return fmt.Errorf("unsupported authentication method: %d", resp[1])
	}
}

func (c *SOCKS5UDPConn) socks5PasswordAuth() error {
	if c.username == "" {
		return errors.New("proxy requires authentication but no credentials provided")
	}

	authReq := make([]byte, 0, 3+len(c.username)+len(c.password))
	authReq = append(authReq, 0x01) // Auth sub-negotiation version
	authReq = append(authReq, byte(len(c.username)))
	authReq = append(authReq, []byte(c.username)...)
	authReq = append(authReq, byte(len(c.password)))
	authReq = append(authReq, []byte(c.password)...)

	if _, err := c.tcpConn.Write(authReq); err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, resp); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if resp[1] != 0x00 {
		return errors.New("authentication failed: invalid credentials")
	}

	return nil
}

func (c *SOCKS5UDPConn) sendUDPAssociate() error {
	request := []byte{
		socks5Version,   // VER
		cmdUDPAssociate, // CMD
		0x00,            // RSV
		atypIPv4,        // ATYP: IPv4
		0, 0, 0, 0,      // DST.ADDR: 0.0.0.0
		0, 0, // DST.PORT: 0
	}

	if _, err := c.tcpConn.Write(request); err != nil {
		return fmt.Errorf("failed to send UDP ASSOCIATE: %w", err)
	}

	return c.parseUDPAssociateReply()
}

func (c *SOCKS5UDPConn) parseUDPAssociateReply() error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(c.tcpConn, header); err != nil {
		return fmt.Errorf("failed to read reply header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("invalid SOCKS version in reply: %d", header[0])
	}

	if header[1] != replySuccess {
		return fmt.Errorf("UDP ASSOCIATE failed: %s", socks5ReplyString(header[1]))
	}

	var relayIP net.IP
	var relayPort uint16

	switch header[3] {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c.tcpConn, addr); err != nil {
			return fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		relayIP = net.IP(addr)

	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(c.tcpConn, lenByte); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(c.tcpConn, domain); err != nil {
			return fmt.Errorf("failed to read domain: %w", err)
		}
		ips, err := net.LookupIP(string(domain))
		if err != nil || len(ips) == 0 {
			return fmt.Errorf("failed to resolve relay domain %s: %w", domain, err)
		}
		relayIP = ips[0]

	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c.tcpConn, addr); err != nil {
			return fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		relayIP = net.IP(addr)

	default:
		return fmt.Errorf("unsupported address type in reply: %d", header[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, portBytes); err != nil {
		return fmt.Errorf("failed to read port: %w", err)
	}
	relayPort = binary.BigEndian.Uint16(portBytes)

	if relayIP.IsUnspecified() {
		proxyIP := net.ParseIP(c.proxyHost)
		if proxyIP == nil {
			ips, err := net.LookupIP(c.proxyHost)
			if err != nil || len(ips) == 0 {
				return fmt.Errorf("failed to resolve proxy host %s: %w", c.proxyHost, err)
			}
			proxyIP = ips[0]
		}
		relayIP = proxyIP
	}

	c.relayAddr = &net.UDPAddr{IP: relayIP, Port: int(relayPort)}
	return nil
}

func (c *SOCKS5UDPConn) tcpKeepalive() {
	buf := make([]byte, 1)
	for {
		c.mu.RLock()
		if c.closed {
			c.mu.RUnlock()
			return
		}
		tcpConn := c.tcpConn
		c.mu.RUnlock()

		if tcpConn == nil {
			return
		}

		tcpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := tcpConn.Read(buf)

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			c.Close()
			return
		}
	}
}

func (c *SOCKS5UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, errors.New("SOCKS5 UDP connection not established")
	}
	udpConn := c.udpConn
	relayAddr := c.relayAddr
	c.mu.RUnlock()

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("invalid address type: %T (expected *net.UDPAddr)", addr)
	}

	header := buildSOCKS5UDPHeader(udpAddr)

	packet := make([]byte, len(header)+len(b))
	copy(packet, header)
	copy(packet[len(header):], b)

	c.mu.RLock()
	deadline := c.writeDeadline
	c.mu.RUnlock()
	if !deadline.IsZero() {
		udpConn.SetWriteDeadline(deadline)
	}

	n, err := udpConn.WriteTo(packet, relayAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to write to relay: %w", err)
	}

	c.mu.Lock()
	c.lastActivity = time.Now()
	c.writeCount++
	c.mu.Unlock()

	dataLen := n - len(header)
	if dataLen < 0 {
		dataLen = 0
	}
	return dataLen, nil
}

func (c *SOCKS5UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return 0, nil, net.ErrClosed
	}
	if !c.established {
		c.mu.RUnlock()
		return 0, nil, errors.New("SOCKS5 UDP connection not established")
	}
	udpConn := c.udpConn
	c.mu.RUnlock()

	c.mu.RLock()
	deadline := c.readDeadline
	c.mu.RUnlock()
	if !deadline.IsZero() {
		udpConn.SetReadDeadline(deadline)
	}

	c.readMu.Lock()
	n, _, err := udpConn.ReadFrom(c.readBuf)
	if err != nil {
		c.readMu.Unlock()
		return 0, nil, err
	}

	dataOffset, srcAddr, err := parseSOCKS5UDPHeader(c.readBuf[:n])
	if err != nil {
		c.readMu.Unlock()
		return 0, nil, fmt.Errorf("invalid SOCKS5 UDP header: %w", err)
	}

	dataLen := n - dataOffset
	if dataLen > len(b) {
		dataLen = len(b)
	}
	copy(b, c.readBuf[dataOffset:dataOffset+dataLen])
	c.readMu.Unlock()

	c.mu.Lock()
	c.lastActivity = time.Now()
	c.mu.Unlock()

	return dataLen, srcAddr, nil
}

func (c *SOCKS5UDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error

	if c.udpConn != nil {
		if err := c.udpConn.Close(); err != nil {
			errs = append(errs, err)
		}
		c.udpConn = nil
	}

	if c.tcpConn != nil {
		if err := c.tcpConn.Close(); err != nil {
			errs = append(errs, err)
		}
		c.tcpConn = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (c *SOCKS5UDPConn) LocalAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.udpConn != nil {
		return c.udpConn.LocalAddr()
	}
	return nil
}

func (c *SOCKS5UDPConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *SOCKS5UDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *SOCKS5UDPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *SOCKS5UDPConn) RelayAddr() *net.UDPAddr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.relayAddr
}

func (c *SOCKS5UDPConn) IsEstablished() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.established
}

func buildSOCKS5UDPHeader(addr *net.UDPAddr) []byte {
	var header []byte

	header = append(header, 0x00, 0x00, 0x00)

	ip := addr.IP
	if ip4 := ip.To4(); ip4 != nil {
		header = append(header, atypIPv4)
		header = append(header, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		header = append(header, atypIPv6)
		header = append(header, ip16...)
	} else {
		header = append(header, atypIPv4, 0, 0, 0, 0)
	}

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(addr.Port))
	header = append(header, port...)

	return header
}

func parseSOCKS5UDPHeader(packet []byte) (dataOffset int, srcAddr net.Addr, err error) {
	if len(packet) < 10 { // Minimum: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + Port(2)
		return 0, nil, errors.New("packet too small")
	}

	if packet[2] != 0x00 {
		return 0, nil, fmt.Errorf("fragmented packets not supported (frag=%d)", packet[2])
	}

	atyp := packet[3]
	var ip net.IP
	var port uint16
	var addrEnd int

	switch atyp {
	case atypIPv4:
		if len(packet) < 10 {
			return 0, nil, errors.New("packet too small for IPv4 address")
		}
		ip = net.IP(packet[4:8])
		port = binary.BigEndian.Uint16(packet[8:10])
		addrEnd = 10

	case atypDomain:
		if len(packet) < 5 {
			return 0, nil, errors.New("packet too small for domain length")
		}
		domainLen := int(packet[4])
		if len(packet) < 7+domainLen {
			return 0, nil, errors.New("packet too small for domain")
		}
		domain := string(packet[5 : 5+domainLen])
		ips, resolveErr := net.LookupIP(domain)
		if resolveErr != nil || len(ips) == 0 {
			ip = net.IPv4zero
		} else {
			ip = ips[0]
		}
		port = binary.BigEndian.Uint16(packet[5+domainLen : 7+domainLen])
		addrEnd = 7 + domainLen

	case atypIPv6:
		if len(packet) < 22 {
			return 0, nil, errors.New("packet too small for IPv6 address")
		}
		ip = net.IP(packet[4:20])
		port = binary.BigEndian.Uint16(packet[20:22])
		addrEnd = 22

	default:
		return 0, nil, fmt.Errorf("unsupported address type: %d", atyp)
	}

	srcAddr = &net.UDPAddr{IP: ip, Port: int(port)}
	return addrEnd, srcAddr, nil
}

func socks5ReplyString(code byte) string {
	switch code {
	case replySuccess:
		return "success"
	case replyGeneralFailure:
		return "general SOCKS server failure"
	case replyConnNotAllowed:
		return "connection not allowed by ruleset"
	case replyNetworkUnreach:
		return "network unreachable"
	case replyHostUnreach:
		return "host unreachable"
	case replyConnRefused:
		return "connection refused"
	case replyTTLExpired:
		return "TTL expired"
	case replyCmdNotSupported:
		return "command not supported"
	case replyAddrNotSupported:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error (code %d)", code)
	}
}
