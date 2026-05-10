package pool

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"io"

	"github.com/jesterfoidchopped/akamai-v3-sensor/dns"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

var (
	ErrPoolClosed    = errors.New("connection pool is closed")
	ErrNoConnections = errors.New("no available connections")
)

type Conn struct {
	Host       string
	RemoteAddr net.Addr
	TLSConn    *utls.UConn
	HTTP2Conn  *http2.ClientConn
	CreatedAt  time.Time
	LastUsedAt time.Time
	UseCount   int64
	mu         sync.Mutex
	closed     bool
}

func (c *Conn) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	if c.HTTP2Conn != nil {
		return c.HTTP2Conn.CanTakeNewRequest()
	}

	return false
}

func (c *Conn) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

func (c *Conn) IdleTime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.LastUsedAt)
}

func (c *Conn) MarkUsed() {
	c.mu.Lock()
	c.LastUsedAt = time.Now()
	c.UseCount++
	c.mu.Unlock()
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.HTTP2Conn != nil {
	}
	if c.TLSConn != nil {
		if err := c.TLSConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

type HostPool struct {
	host        string // Connection host (for DNS resolution - may be connectTo target)
	sniHost     string // SNI host (for TLS ServerName - always the original request host)
	port        string
	preset      *fingerprint.Preset
	dnsCache    *dns.Cache
	connections []*Conn
	mu          sync.Mutex

	sessionCache utls.ClientSessionCache

	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec

	shuffleSeed int64

	maxConns           int
	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	insecureSkipVerify bool
	proxyURL           string
	localAddr          string // Local IP to bind outgoing connections

	echConfig       []byte // Custom ECH configuration
	echConfigDomain string // Domain to fetch ECH config from
}

func NewHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *HostPool {
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	var cachedSpec, cachedPSKSpec *utls.ClientHelloSpec
	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			cachedSpec = spec
		}
	} else if spec, err := utls.UTLSIdToSpecWithSeed(preset.ClientHelloID, shuffleSeed); err == nil {
		cachedSpec = &spec
	}
	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.PSKClientHelloID, shuffleSeed); err == nil {
			cachedPSKSpec = &spec
		}
	}
	return NewHostPoolWithConfig(host, "", port, preset, dnsCache, false, "", cachedSpec, cachedPSKSpec, shuffleSeed, nil)
}

func NewHostPoolWithConfig(host, sniHost, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, insecureSkipVerify bool, proxyURL string, cachedSpec, cachedPSKSpec *utls.ClientHelloSpec, shuffleSeed int64, sessionCache utls.ClientSessionCache) *HostPool {
	if sessionCache == nil {
		sessionCache = utls.NewLRUClientSessionCache(32)
	}
	if sniHost == "" {
		sniHost = host
	}
	pool := &HostPool{
		host:               host,
		sniHost:            sniHost,
		port:               port,
		preset:             preset,
		dnsCache:           dnsCache,
		connections:        make([]*Conn, 0),
		sessionCache:       sessionCache, // Use shared session cache for persistence
		maxConns:           0,            // 0 = unlimited connections
		maxIdleTime:        90 * time.Second,
		maxConnAge:         5 * time.Minute,
		connectTimeout:     30 * time.Second,
		insecureSkipVerify: insecureSkipVerify,
		proxyURL:           proxyURL,
		cachedSpec:         cachedSpec,    // Reference spec (for availability check)
		cachedPSKSpec:      cachedPSKSpec, // Reference PSK spec (for availability check)
		shuffleSeed:        shuffleSeed,   // Seed for generating fresh specs per connection
	}

	return pool
}

func (p *HostPool) SetMaxConns(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = max
}

func (p *HostPool) SetECHConfig(echConfig []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.echConfig = echConfig
}

func (p *HostPool) SetECHConfigDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.echConfigDomain = domain
}

func (p *HostPool) SetLocalAddr(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.localAddr = addr
}

func (p *HostPool) GetConn(ctx context.Context) (*Conn, error) {
	p.mu.Lock()

	for i, conn := range p.connections {
		if conn.IsHealthy() && conn.IdleTime() < p.maxIdleTime && conn.Age() < p.maxConnAge {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			p.connections = append(p.connections, conn)
			p.mu.Unlock()
			conn.MarkUsed()
			return conn, nil
		}
	}

	healthy := make([]*Conn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IsHealthy() && conn.Age() < p.maxConnAge {
			healthy = append(healthy, conn)
		} else {
			go conn.Close()
		}
	}
	p.connections = healthy

	if p.maxConns > 0 && len(p.connections) >= p.maxConns {
		p.mu.Unlock()
		return nil, ErrNoConnections
	}

	p.mu.Unlock()

	conn, err := p.createConn(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.connections = append(p.connections, conn)
	p.mu.Unlock()

	return conn, nil
}

func (p *HostPool) createConn(ctx context.Context) (*Conn, error) {
	var rawConn net.Conn
	var err error

	if p.proxyURL != "" {
		rawConn, err = p.dialThroughProxy(ctx)
		if err != nil {
			return nil, fmt.Errorf("proxy connect failed: %w", err)
		}
	} else {
		ipv6, ipv4, err := p.dnsCache.ResolveIPv6First(ctx, p.host)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}

		var preferredIPs, fallbackIPs []net.IP
		if p.dnsCache.PreferIPv4() {
			preferredIPs = ipv4
			fallbackIPs = ipv6
		} else {
			preferredIPs = ipv6
			fallbackIPs = ipv4
		}

		rawConn, err = p.dialHappyEyeballs(ctx, preferredIPs, fallbackIPs)
		if err != nil {
			return nil, fmt.Errorf("TCP connect failed: %w", err)
		}
	}

	var echConfigList []byte
	if len(p.echConfig) > 0 {
		echConfigList = p.echConfig
	} else if p.echConfigDomain != "" {
		echConfigList, err = dns.FetchECHConfigs(ctx, p.echConfigDomain)
		if err != nil {
			echConfigList = nil
		}
	}

	minVersion := uint16(tls.VersionTLS12)
	if len(echConfigList) > 0 {
		minVersion = tls.VersionTLS13
	}

	var keyLogWriter io.Writer = transport.GetKeyLogWriter()

	hasPSK := p.cachedPSKSpec != nil || (p.preset.JA3 != "" && fingerprint.JA3HasExtension(p.preset.JA3, "41"))
	var sessionCache utls.ClientSessionCache
	if hasPSK {
		sessionCache = p.sessionCache
	}

	tlsConfig := &utls.Config{
		ServerName:                         p.sniHost,
		InsecureSkipVerify:                 p.insecureSkipVerify,
		MinVersion:                         minVersion,
		MaxVersion:                         tls.VersionTLS13,
		SessionTicketsDisabled:             false,         // Enable session tickets
		ClientSessionCache:                 sessionCache,  // Only set when PSK is available
		OmitEmptyPsk:                       true,          // Chrome doesn't send empty PSK on first connection
		PreferSkipResumptionOnNilExtension: true,          // Safety net: skip resumption if spec lacks PSK extension
		EncryptedClientHelloConfigList:     echConfigList, // ECH configuration (if available)
		KeyLogWriter:                       keyLogWriter,
	}

	var specToUse *utls.ClientHelloSpec
	var tlsConn *utls.UConn

	if p.preset.JA3 != "" {
		spec, err := fingerprint.ParseJA3(p.preset.JA3, p.preset.JA3Extras)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to parse JA3: %w", err)
		}
		specToUse = spec
	} else if p.cachedPSKSpec != nil && p.preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(p.preset.PSKClientHelloID, p.shuffleSeed); err == nil {
			specToUse = &spec
		}
	}
	if specToUse == nil && p.cachedSpec != nil && p.preset.JA3 == "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(p.preset.ClientHelloID, p.shuffleSeed); err == nil {
			specToUse = &spec
		}
	}

	if specToUse != nil {
		tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(specToUse); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply TLS preset: %w", err)
		}
	} else {
		clientHelloID := p.preset.ClientHelloID
		if p.preset.PSKClientHelloID.Client != "" {
			clientHelloID = p.preset.PSKClientHelloID
		}
		tlsConn = utls.UClient(rawConn, tlsConfig, clientHelloID)
	}

	if p.cachedPSKSpec != nil || (p.preset.JA3 != "" && fingerprint.JA3HasExtension(p.preset.JA3, "41")) {
		tlsConn.SetSessionCache(p.sessionCache)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	settings := p.preset.HTTP2Settings

	h2Transport := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         false,
		StrictMaxConcurrentStreams: false,
		MaxHeaderListSize:          settings.MaxHeaderListSize,
		MaxReadFrameSize:           settings.MaxFrameSize,
		MaxDecoderHeaderTableSize:  settings.HeaderTableSize,
		MaxEncoderHeaderTableSize:  settings.HeaderTableSize,

		ConnectionFlow: settings.ConnectionWindowUpdate,
		Settings:       buildHTTP2Settings(settings),
		SettingsOrder:  buildHTTP2SettingsOrder(settings, p.preset),
		PseudoHeaderOrder: func() []string {
			if order := p.preset.H2PseudoHeaderOrder(); order != nil {
				return order
			}
			if settings.NoRFC7540Priorities {
				return []string{":method", ":scheme", ":path", ":authority"} // Safari order (m,s,p,a)
			}
			return []string{":method", ":authority", ":scheme", ":path"} // Chrome order (m,a,s,p)
		}(),
		HeaderPriority: func() *http2.PriorityParam {
			if settings.StreamWeight > 0 {
				return &http2.PriorityParam{
					Weight:    uint8(settings.StreamWeight - 1), // Wire format is weight-1
					Exclusive: settings.StreamExclusive,
					StreamDep: 0,
				}
			}
			return nil
		}(),
		HeaderOrder:         p.preset.H2HeaderOrder(),
		UserAgent:           p.preset.UserAgent,
		StreamPriorityMode:  resolveStreamPriorityMode(p.preset.H2StreamPriorityMode()),
		HPACKIndexingPolicy: resolveHPACKIndexingPolicy(p.preset.H2HPACKIndexingPolicy()),
		HPACKNeverIndex:     p.preset.H2HPACKNeverIndex(),
		DisableCookieSplit:  p.preset.H2DisableCookieSplit(),
	}

	h2Conn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}

	conn := &Conn{
		Host:       p.host,
		RemoteAddr: rawConn.RemoteAddr(),
		TLSConn:    tlsConn,
		HTTP2Conn:  h2Conn,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		UseCount:   0,
	}

	return conn, nil
}

func (p *HostPool) dialHappyEyeballs(ctx context.Context, preferredIPs, fallbackIPs []net.IP) (net.Conn, error) {
	if p.localAddr != "" {
		localIP := net.ParseIP(p.localAddr)
		if localIP != nil {
			isLocalIPv6 := localIP.To4() == nil
			filterByFamily := func(ips []net.IP) []net.IP {
				var filtered []net.IP
				for _, ip := range ips {
					isIPv6 := ip.To4() == nil
					if isIPv6 == isLocalIPv6 {
						filtered = append(filtered, ip)
					}
				}
				return filtered
			}
			preferredIPs = filterByFamily(preferredIPs)
			fallbackIPs = filterByFamily(fallbackIPs)
		}
	}

	totalIPs := len(preferredIPs) + len(fallbackIPs)
	if totalIPs == 0 {
		return nil, fmt.Errorf("no IP addresses available")
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	dialCtx, cancel := context.WithCancel(ctx)
	resultCh := make(chan dialResult, totalIPs)
	perAddrTimeout := 5 * time.Second
	started := 0

	startDial := func(ip net.IP) {
		go func(ip net.IP) {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), p.port)
			dialer := &net.Dialer{Timeout: perAddrTimeout}
			transport.SetDialerControl(dialer, &p.preset.TCPFingerprint)
			if p.localAddr != "" {
				dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.localAddr)}
			}
			conn, err := dialer.DialContext(dialCtx, network, addr)
			select {
			case resultCh <- dialResult{conn: conn, err: err}:
			case <-dialCtx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}(ip)
	}

	for _, ip := range preferredIPs {
		startDial(ip)
		started++
	}

	if len(fallbackIPs) > 0 {
		select {
		case result := <-resultCh:
			if result.conn != nil {
				cancel()
				return result.conn, nil
			}
			started-- // One failed, adjust count
		case <-time.After(250 * time.Millisecond):
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}

		for _, ip := range fallbackIPs {
			startDial(ip)
			started++
		}
	}

	var lastErr error
	for i := 0; i < started; i++ {
		select {
		case result := <-resultCh:
			if result.conn != nil {
				cancel()
				return result.conn, nil
			}
			lastErr = result.err
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	}

	cancel()
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all connection attempts failed")
}

func (p *HostPool) dialThroughProxy(ctx context.Context) (net.Conn, error) {
	proxyURL, err := parseProxyURL(p.proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	switch proxyURL.Scheme {
	case "http", "https":
		return p.dialHTTPProxy(ctx, proxyURL)
	case "socks5", "socks5h":
		return p.dialSOCKS5Proxy(ctx, proxyURL)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
}

func parseProxyURL(proxyURL string) (*proxyConfig, error) {
	if !hasScheme(proxyURL) {
		proxyURL = "http://" + proxyURL
	}

	scheme := "http"
	rest := proxyURL

	if idx := indexOf(proxyURL, "://"); idx != -1 {
		scheme = proxyURL[:idx]
		rest = proxyURL[idx+3:]
	}

	var username, password string
	if idx := indexOf(rest, "@"); idx != -1 {
		userInfo := rest[:idx]
		rest = rest[idx+1:]
		if pwIdx := indexOf(userInfo, ":"); pwIdx != -1 {
			username = userInfo[:pwIdx]
			password = userInfo[pwIdx+1:]
		} else {
			username = userInfo
		}
	}

	host := rest
	port := ""
	if idx := lastIndexOf(rest, ":"); idx != -1 {
		host = rest[:idx]
		port = rest[idx+1:]
	}

	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		}
	}

	return &proxyConfig{
		Scheme:   scheme,
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
	}, nil
}

type proxyConfig struct {
	Scheme   string
	Host     string
	Port     string
	Username string
	Password string
}

func (p *proxyConfig) Addr() string {
	return net.JoinHostPort(p.Host, p.Port)
}

func hasScheme(url string) bool {
	return indexOf(url, "://") != -1
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func lastIndexOf(s, substr string) int {
	for i := len(s) - len(substr); i >= 0; i-- {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func (p *HostPool) dialHTTPProxy(ctx context.Context, proxy *proxyConfig) (net.Conn, error) {
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxy.Host, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxy.Host)
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}
	transport.SetDialerControl(dialer, &p.preset.TCPFingerprint)
	if p.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.localAddr)}
	}
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	targetAddr := net.JoinHostPort(p.host, p.port)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	if proxy.Username != "" {
		auth := proxy.Username + ":" + proxy.Password
		encoded := base64.StdEncoding.EncodeToString([]byte(auth))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encoded)
	}

	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}

	response := string(buf[:n])
	if !isHTTP200(response) {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", getFirstLine(response))
	}

	return conn, nil
}

func (p *HostPool) dialSOCKS5Proxy(ctx context.Context, proxy *proxyConfig) (net.Conn, error) {
	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxy.Host, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxy.Host)
	}

	dialer := &net.Dialer{Timeout: p.connectTimeout}
	transport.SetDialerControl(dialer, &p.preset.TCPFingerprint)
	if p.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(p.localAddr)}
	}
	proxyAddr := net.JoinHostPort(proxyIPs[0], proxy.Port)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}

	var authMethods []byte
	if proxy.Username != "" {
		authMethods = []byte{0x05, 0x02, 0x00, 0x02} // No auth and username/password
	} else {
		authMethods = []byte{0x05, 0x01, 0x00} // No auth only
	}

	if _, err := conn.Write(authMethods); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 auth response failed: %w", err)
	}

	if resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version: %d", resp[0])
	}

	switch resp[1] {
	case 0x00:
	case 0x02:
		if err := p.socks5Auth(conn, proxy); err != nil {
			conn.Close()
			return nil, err
		}
	case 0xFF:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: no acceptable auth methods")
	default:
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: unsupported auth method: %d", resp[1])
	}

	targetPort, _ := parsePort(p.port)
	var connectReq []byte

	if ip := net.ParseIP(p.host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			connectReq = append([]byte{0x05, 0x01, 0x00, 0x01}, ip4...)
		} else {
			connectReq = append([]byte{0x05, 0x01, 0x00, 0x04}, ip...)
		}
	} else {
		connectReq = []byte{0x05, 0x01, 0x00, 0x03, byte(len(p.host))}
		connectReq = append(connectReq, []byte(p.host)...)
	}

	connectReq = append(connectReq, byte(targetPort>>8), byte(targetPort))

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect request failed: %w", err)
	}

	respBuf := make([]byte, 10)
	if _, err := conn.Read(respBuf); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect response failed: %w", err)
	}

	if respBuf[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5: invalid version in response")
	}

	if respBuf[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed with code: %d", respBuf[1])
	}

	return conn, nil
}

func (p *HostPool) socks5Auth(conn net.Conn, proxy *proxyConfig) error {
	authReq := []byte{0x01, byte(len(proxy.Username))}
	authReq = append(authReq, []byte(proxy.Username)...)
	authReq = append(authReq, byte(len(proxy.Password)))
	authReq = append(authReq, []byte(proxy.Password)...)

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("SOCKS5 auth request failed: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return fmt.Errorf("SOCKS5 auth response failed: %w", err)
	}

	if resp[1] != 0x00 {
		return fmt.Errorf("SOCKS5 authentication failed")
	}

	return nil
}

func parsePort(port string) (int, error) {
	var p int
	for _, c := range port {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid port: %s", port)
		}
		p = p*10 + int(c-'0')
	}
	return p, nil
}

func isHTTP200(response string) bool {
	return len(response) >= 12 && response[9] == '2' && response[10] == '0' && response[11] == '0'
}

func getFirstLine(s string) string {
	for i, c := range s {
		if c == '\r' || c == '\n' {
			return s[:i]
		}
	}
	return s
}

func (p *HostPool) CloseIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	active := make([]*Conn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IdleTime() > p.maxIdleTime || conn.Age() > p.maxConnAge || !conn.IsHealthy() {
			go conn.Close()
		} else {
			active = append(active, conn)
		}
	}
	p.connections = active
}

func (p *HostPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = nil
}

func (p *HostPool) Stats() (total int, healthy int, totalRequests int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		total++
		if conn.IsHealthy() {
			healthy++
		}
		totalRequests += conn.UseCount
	}
	return
}

type Manager struct {
	pools    map[string]*HostPool
	mu       sync.RWMutex
	dnsCache *dns.Cache
	preset   *fingerprint.Preset
	closed   bool

	maxConnsPerHost    int               // 0 = unlimited
	proxyURL           string            // Proxy URL (optional)
	insecureSkipVerify bool              // Skip TLS verification
	connectTo          map[string]string // Domain fronting: request host -> connect host
	echConfig          []byte            // Custom ECH configuration
	echConfigDomain    string            // Domain to fetch ECH config from

	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec
	shuffleSeed   int64 // Seed used for extension shuffling

	sessionCache utls.ClientSessionCache

	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

func NewManager(preset *fingerprint.Preset) *Manager {
	return NewManagerWithTLSConfig(preset, false)
}

func NewManagerWithTLSConfig(preset *fingerprint.Preset, insecureSkipVerify bool) *Manager {
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		insecureSkipVerify: insecureSkipVerify,
		shuffleSeed:        shuffleSeed,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			m.cachedSpec = spec
		}
	} else if spec, err := utls.UTLSIdToSpecWithSeed(preset.ClientHelloID, shuffleSeed); err == nil {
		m.cachedSpec = &spec
	}

	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.PSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = &spec
		}
	}

	go m.cleanupLoop()

	return m
}

func NewManagerWithProxy(preset *fingerprint.Preset, proxyURL string, insecureSkipVerify bool) *Manager {
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &Manager{
		pools:              make(map[string]*HostPool),
		dnsCache:           dns.NewCache(),
		preset:             preset,
		maxConnsPerHost:    0, // 0 = unlimited by default
		proxyURL:           proxyURL,
		insecureSkipVerify: insecureSkipVerify,
		shuffleSeed:        shuffleSeed,
		cleanupInterval:    30 * time.Second,
		stopCleanup:        make(chan struct{}),
	}

	if preset.JA3 != "" {
		if spec, err := fingerprint.ParseJA3(preset.JA3, preset.JA3Extras); err == nil {
			m.cachedSpec = spec
		}
	} else if spec, err := utls.UTLSIdToSpecWithSeed(preset.ClientHelloID, shuffleSeed); err == nil {
		m.cachedSpec = &spec
	}

	if preset.JA3 == "" && preset.PSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.PSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = &spec
		}
	}

	go m.cleanupLoop()

	return m
}

func (m *Manager) SetMaxConnsPerHost(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxConnsPerHost = max
}

func (m *Manager) SetSessionCache(cache utls.ClientSessionCache) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessionCache = cache
}

func (m *Manager) GetSessionCache() utls.ClientSessionCache {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessionCache
}

func (m *Manager) GetPool(host, port string) (*HostPool, error) {
	if port == "" {
		port = "443"
	}

	connectHost := host
	if m.connectTo != nil {
		if mapped, ok := m.connectTo[host]; ok {
			connectHost = mapped
		}
	}
	key := net.JoinHostPort(connectHost, port)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	pool, exists := m.pools[key]
	m.mu.RUnlock()

	if exists {
		return pool, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrPoolClosed
	}

	if pool, exists = m.pools[key]; exists {
		return pool, nil
	}

	sniHost := ""
	if connectHost != host {
		sniHost = host // Original request host for TLS ServerName
	}
	pool = NewHostPoolWithConfig(connectHost, sniHost, port, m.preset, m.dnsCache, m.insecureSkipVerify, m.proxyURL, m.cachedSpec, m.cachedPSKSpec, m.shuffleSeed, m.sessionCache)
	if m.maxConnsPerHost > 0 {
		pool.SetMaxConns(m.maxConnsPerHost)
	}
	if len(m.echConfig) > 0 {
		pool.SetECHConfig(m.echConfig)
	}
	if m.echConfigDomain != "" {
		pool.SetECHConfigDomain(m.echConfigDomain)
	}
	m.pools[key] = pool
	return pool, nil
}

func (m *Manager) GetConn(ctx context.Context, host, port string) (*Conn, error) {
	pool, err := m.GetPool(host, port)
	if err != nil {
		return nil, err
	}
	return pool.GetConn(ctx)
}

func (m *Manager) SetPreset(preset *fingerprint.Preset) {
	m.mu.Lock()
	m.preset = preset
	m.mu.Unlock()
}

func (m *Manager) GetDNSCache() *dns.Cache {
	return m.dnsCache
}

func (m *Manager) SetConnectTo(requestHost, connectHost string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectTo == nil {
		m.connectTo = make(map[string]string)
	}
	m.connectTo[requestHost] = connectHost
}

func (m *Manager) SetECHConfig(echConfig []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfig = echConfig
}

func (m *Manager) SetECHConfigDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfigDomain = domain
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, pool := range m.pools {
		pool.CloseIdle()
		total, _, _ := pool.Stats()
		if total == 0 {
			delete(m.pools, key)
		}
	}

	m.dnsCache.Cleanup()
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}
	m.closed = true

	close(m.stopCleanup)

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = nil
}

func (m *Manager) CloseAllPools() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = make(map[string]*HostPool)
}

func (m *Manager) SetProxy(proxyURL string) {
	m.CloseAllPools()
	m.mu.Lock()
	m.proxyURL = proxyURL
	m.mu.Unlock()
}

func (m *Manager) GetProxy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyURL
}

func (m *Manager) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]struct {
		Total    int
		Healthy  int
		Requests int64
	})

	for key, pool := range m.pools {
		t, h, r := pool.Stats()
		stats[key] = struct {
			Total    int
			Healthy  int
			Requests int64
		}{t, h, r}
	}

	return stats
}

func resolveStreamPriorityMode(mode string) http2.StreamPriorityMode {
	switch mode {
	case "chrome":
		return http2.StreamPriorityChrome
	case "default":
		return http2.StreamPriorityDefault
	default:
		return http2.StreamPriorityChrome
	}
}

func resolveHPACKIndexingPolicy(policy string) hpack.IndexingPolicy {
	switch policy {
	case "chrome":
		return hpack.IndexingChrome
	case "never":
		return hpack.IndexingNever
	case "always":
		return hpack.IndexingAlways
	case "default":
		return hpack.IndexingDefault
	default:
		return hpack.IndexingChrome
	}
}

func uint16sToSettingIDs(ids []uint16) []http2.SettingID {
	result := make([]http2.SettingID, len(ids))
	for i, id := range ids {
		result[i] = http2.SettingID(id)
	}
	return result
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

func buildHTTP2Settings(settings fingerprint.HTTP2Settings) map[http2.SettingID]uint32 {
	h2Settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   settings.HeaderTableSize,
		http2.SettingEnablePush:        boolToUint32(settings.EnablePush),
		http2.SettingInitialWindowSize: settings.InitialWindowSize,
		http2.SettingMaxHeaderListSize: settings.MaxHeaderListSize,
	}
	if settings.MaxConcurrentStreams > 0 {
		h2Settings[http2.SettingMaxConcurrentStreams] = settings.MaxConcurrentStreams
	}
	if settings.MaxFrameSize > 0 {
		h2Settings[http2.SettingMaxFrameSize] = settings.MaxFrameSize
	}
	if settings.NoRFC7540Priorities {
		h2Settings[http2.SettingNoRFC7540Priorities] = 1
	}
	return h2Settings
}

func buildHTTP2SettingsOrder(settings fingerprint.HTTP2Settings, preset *fingerprint.Preset) []http2.SettingID {
	if order := preset.H2SettingsOrder(); order != nil {
		return uint16sToSettingIDs(order)
	}
	var order []http2.SettingID
	if settings.NoRFC7540Priorities {
		order = []http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
		}
	} else {
		order = []http2.SettingID{
			http2.SettingHeaderTableSize,
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxHeaderListSize,
		}
	}
	if settings.MaxConcurrentStreams > 0 {
		order = append(order, http2.SettingMaxConcurrentStreams)
	}
	if settings.MaxFrameSize > 0 {
		order = append(order, http2.SettingMaxFrameSize)
	}
	if settings.NoRFC7540Priorities {
		order = append(order, http2.SettingNoRFC7540Priorities)
	}
	return order
}
