package sensor

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/proxy"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
)

const (
	HeaderUpstreamProxy = "X-Upstream-Proxy"

	HeaderTLSOnly = "X-HTTPCloak-TlsOnly"

	HeaderSession = "X-HTTPCloak-Session"

	HeaderScheme = "X-HTTPCloak-Scheme"

	ProxyAuthScheme = "HTTPCloak"
)

type LocalProxy struct {
	listener net.Listener
	port     int

	preset         string
	timeout        time.Duration
	maxConnections int
	tcpProxy       string // Upstream proxy for TCP connections
	udpProxy       string // Upstream proxy for UDP connections
	tlsOnly        bool   // TLS-only mode: skip preset HTTP headers

	session   *Session
	sessionMu sync.RWMutex

	sessionRegistry   map[string]*Session
	sessionRegistryMu sync.RWMutex

	httpClient *http.Client
	transport  *http.Transport

	running      atomic.Bool
	activeConns  atomic.Int64
	totalReqs    atomic.Int64
	shuttingDown atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type LocalProxyConfig struct {
	Port int

	Preset string

	Timeout time.Duration

	MaxConnections int

	TCPProxy string
	UDPProxy string

	TLSOnly bool

	SessionCacheBackend transport.SessionCacheBackend

	SessionCacheErrorCallback transport.ErrorCallback
}

type LocalProxyOption func(*LocalProxyConfig)

func WithProxyPreset(preset string) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.Preset = preset
	}
}

func WithProxyTimeout(d time.Duration) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.Timeout = d
	}
}

func WithProxyMaxConnections(n int) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.MaxConnections = n
	}
}

func WithProxyUpstream(tcpProxy, udpProxy string) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.TCPProxy = tcpProxy
		c.UDPProxy = udpProxy
	}
}

func WithProxyTLSOnly() LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.TLSOnly = true
	}
}

func WithProxySessionCache(backend transport.SessionCacheBackend, errorCallback transport.ErrorCallback) LocalProxyOption {
	return func(c *LocalProxyConfig) {
		c.SessionCacheBackend = backend
		c.SessionCacheErrorCallback = errorCallback
	}
}

func StartLocalProxy(port int, opts ...LocalProxyOption) (*LocalProxy, error) {
	config := &LocalProxyConfig{
		Port:           port,
		Preset:         "chrome-146",
		Timeout:        30 * time.Second,
		MaxConnections: 1000,
	}

	for _, opt := range opts {
		opt(config)
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &LocalProxy{
		port:            config.Port,
		preset:          config.Preset,
		timeout:         config.Timeout,
		maxConnections:  config.MaxConnections,
		tcpProxy:        config.TCPProxy,
		udpProxy:        config.UDPProxy,
		tlsOnly:         config.TLSOnly,
		sessionRegistry: make(map[string]*Session),
		ctx:             ctx,
		cancel:          cancel,
	}

	sessionOpts := []SessionOption{
		WithSessionTimeout(config.Timeout),
	}
	if config.TCPProxy != "" {
		sessionOpts = append(sessionOpts, WithSessionTCPProxy(config.TCPProxy))
	}
	if config.UDPProxy != "" {
		sessionOpts = append(sessionOpts, WithSessionUDPProxy(config.UDPProxy))
	}
	if config.TLSOnly {
		sessionOpts = append(sessionOpts, WithTLSOnly())
	}
	if config.SessionCacheBackend != nil {
		sessionOpts = append(sessionOpts, WithSessionCache(config.SessionCacheBackend, config.SessionCacheErrorCallback))
	}
	p.session = NewSession(config.Preset, sessionOpts...)

	p.transport = &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Let client handle compression
		WriteBufferSize:     64 * 1024,
		ReadBufferSize:      64 * 1024,
		ForceAttemptHTTP2:   false, // Keep HTTP/1.1 for simplicity
	}
	p.httpClient = &http.Client{
		Transport: p.transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	if err := p.start(); err != nil {
		p.session.Close()
		p.transport.CloseIdleConnections()
		cancel()
		return nil, err
	}

	return p, nil
}

func (p *LocalProxy) start() error {
	if p.running.Load() {
		return errors.New("proxy already running")
	}

	addr := fmt.Sprintf("127.0.0.1:%d", p.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	p.listener = listener
	p.running.Store(true)

	if p.port == 0 {
		p.port = listener.Addr().(*net.TCPAddr).Port
	}

	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

func (p *LocalProxy) Stop() error {
	if !p.running.Load() {
		return nil
	}

	p.shuttingDown.Store(true)
	p.cancel()

	if p.listener != nil {
		p.listener.Close()
	}

	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}

	if p.session != nil {
		p.session.Close()
	}
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}

	p.running.Store(false)
	return nil
}

func (p *LocalProxy) Port() int {
	return p.port
}

func (p *LocalProxy) IsRunning() bool {
	return p.running.Load()
}

func (p *LocalProxy) Stats() map[string]interface{} {
	p.sessionRegistryMu.RLock()
	sessionCount := len(p.sessionRegistry)
	p.sessionRegistryMu.RUnlock()

	return map[string]interface{}{
		"running":             p.running.Load(),
		"port":                p.port,
		"active_conns":        p.activeConns.Load(),
		"total_requests":      p.totalReqs.Load(),
		"preset":              p.preset,
		"max_connections":     p.maxConnections,
		"registered_sessions": sessionCount,
	}
}

func (p *LocalProxy) RegisterSession(sessionID string, session *Session) error {
	p.sessionRegistryMu.Lock()
	defer p.sessionRegistryMu.Unlock()

	if _, exists := p.sessionRegistry[sessionID]; exists {
		return fmt.Errorf("session with ID %q already exists", sessionID)
	}

	session.SetSessionIdentifier(sessionID)

	p.sessionRegistry[sessionID] = session
	return nil
}

func (p *LocalProxy) UnregisterSession(sessionID string) *Session {
	p.sessionRegistryMu.Lock()
	defer p.sessionRegistryMu.Unlock()

	session, exists := p.sessionRegistry[sessionID]
	if !exists {
		return nil
	}

	session.SetSessionIdentifier("")

	delete(p.sessionRegistry, sessionID)
	return session
}

func (p *LocalProxy) GetSession(sessionID string) *Session {
	p.sessionRegistryMu.RLock()
	defer p.sessionRegistryMu.RUnlock()
	return p.sessionRegistry[sessionID]
}

func (p *LocalProxy) ListSessions() []string {
	p.sessionRegistryMu.RLock()
	defer p.sessionRegistryMu.RUnlock()

	ids := make([]string, 0, len(p.sessionRegistry))
	for id := range p.sessionRegistry {
		ids = append(ids, id)
	}
	return ids
}

func (p *LocalProxy) extractSessionID(req *http.Request) string {
	return req.Header.Get(HeaderSession)
}

func (p *LocalProxy) acceptLoop() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.shuttingDown.Load() {
				return
			}
			continue
		}

		if p.activeConns.Load() >= int64(p.maxConnections) {
			conn.Close()
			continue
		}

		p.activeConns.Add(1)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.activeConns.Add(-1)
			p.handleConnection(conn)
		}()
	}
}

func (p *LocalProxy) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		p.sendError(conn, http.StatusBadRequest, "Bad Request")
		return
	}

	conn.SetReadDeadline(time.Time{})

	p.totalReqs.Add(1)

	if req.Method == http.MethodConnect {
		p.handleCONNECT(conn, req)
	} else {
		p.handleHTTP(conn, req, reader)
	}
}

func (p *LocalProxy) handleCONNECT(clientConn net.Conn, req *http.Request) {
	targetHost := req.Host
	if targetHost == "" {
		targetHost = req.URL.Host
	}

	host, port, err := net.SplitHostPort(targetHost)
	if err != nil {
		host = targetHost
		port = "443"
		targetHost = net.JoinHostPort(host, port)
	}

	if !p.isPortAllowed(port) {
		p.sendError(clientConn, http.StatusForbidden, "Port not allowed")
		return
	}

	proxyOverride := p.extractUpstreamProxy(req)

	ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
	defer cancel()

	targetConn, err := p.dialTarget(ctx, host, port, proxyOverride)
	if err != nil {
		p.sendError(clientConn, http.StatusBadGateway, fmt.Sprintf("Failed to connect: %v", err))
		return
	}
	defer targetConn.Close()

	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := clientConn.Write([]byte(response)); err != nil {
		return
	}

	p.tunnel(clientConn, targetConn)
}

func (p *LocalProxy) handleHTTP(clientConn net.Conn, req *http.Request, reader *bufio.Reader) {
	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		if req.URL.Host != "" {
			targetURL = "http://" + req.URL.Host + req.URL.RequestURI()
		} else if req.Host != "" {
			targetURL = "http://" + req.Host + req.URL.RequestURI()
		} else {
			p.sendError(clientConn, http.StatusBadRequest, "Missing host")
			return
		}
	}

	schemeOverride := req.Header.Get(HeaderScheme)
	if strings.EqualFold(schemeOverride, "https") && strings.HasPrefix(targetURL, "http://") {
		targetURL = "https://" + strings.TrimPrefix(targetURL, "http://")
	}

	ctx, cancel := context.WithTimeout(p.ctx, p.timeout)
	defer cancel()

	if strings.HasPrefix(targetURL, "https://") {
		p.handleHTTPWithSession(ctx, clientConn, req, targetURL)
		return
	}

	p.handleHTTPDirect(ctx, clientConn, req, targetURL)
}

func (p *LocalProxy) handleHTTPWithSession(ctx context.Context, clientConn net.Conn, req *http.Request, targetURL string) {
	session := p.session
	sessionID := p.extractSessionID(req)
	if sessionID != "" {
		if registeredSession := p.GetSession(sessionID); registeredSession != nil {
			session = registeredSession
		} else {
			p.sendError(clientConn, http.StatusBadRequest, fmt.Sprintf("Session not found: %s", sessionID))
			return
		}
	}

	var tlsOnlyOverride *bool
	if tlsOnlyValue, hasTLSOnlyHeader := p.extractTLSOnly(req); hasTLSOnlyHeader {
		tlsOnlyOverride = &tlsOnlyValue
	}

	headers := make(map[string][]string)
	for key, values := range req.Header {
		if isHopByHopHeader(key) {
			continue
		}
		if strings.EqualFold(key, HeaderUpstreamProxy) ||
			strings.EqualFold(key, HeaderTLSOnly) ||
			strings.EqualFold(key, HeaderSession) ||
			strings.EqualFold(key, HeaderScheme) {
			continue
		}
		if strings.EqualFold(key, "Proxy-Authorization") {
			if len(values) > 0 && strings.HasPrefix(values[0], ProxyAuthScheme+" ") {
				continue
			}
		}
		headers[key] = values
	}

	hcReq := &Request{
		Method:  req.Method,
		URL:     targetURL,
		Headers: headers,
		Body:    req.Body, // Streaming request body
		TLSOnly: tlsOnlyOverride,
	}

	resp, err := session.DoStream(ctx, hcReq)
	if err != nil {
		p.sendError(clientConn, http.StatusBadGateway, fmt.Sprintf("Request failed: %v", err))
		return
	}
	defer resp.Close()

	bufWriter := bufio.NewWriterSize(clientConn, 64*1024)

	fmt.Fprintf(bufWriter, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))

	for key, values := range resp.Headers {
		if isHopByHopHeader(key) {
			continue
		}
		if strings.EqualFold(key, "Content-Encoding") {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(bufWriter, "%s: %s\r\n", key, value)
		}
	}
	bufWriter.WriteString("\r\n")
	bufWriter.Flush()

	buf := make([]byte, 64*1024) // 64KB buffer
	io.CopyBuffer(clientConn, resp, buf)
}

func (p *LocalProxy) handleHTTPDirect(ctx context.Context, clientConn net.Conn, req *http.Request, targetURL string) {
	proxyOverride := p.extractUpstreamProxy(req)

	outReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
	if err != nil {
		p.sendError(clientConn, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	for key, values := range req.Header {
		if isHopByHopHeader(key) {
			continue
		}
		if strings.EqualFold(key, HeaderUpstreamProxy) ||
			strings.EqualFold(key, HeaderTLSOnly) ||
			strings.EqualFold(key, HeaderSession) ||
			strings.EqualFold(key, HeaderScheme) {
			continue
		}
		if strings.EqualFold(key, "Proxy-Authorization") {
			if len(values) > 0 && strings.HasPrefix(values[0], ProxyAuthScheme+" ") {
				continue
			}
		}
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}
	outReq.ContentLength = req.ContentLength

	client := p.httpClient
	if proxyOverride != "" {
		client = p.createProxyClient(proxyOverride)
	}

	resp, err := client.Do(outReq)
	if err != nil {
		p.sendError(clientConn, http.StatusBadGateway, fmt.Sprintf("Request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	bufWriter := bufio.NewWriterSize(clientConn, 64*1024)

	fmt.Fprintf(bufWriter, "HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)

	for key, values := range resp.Header {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(bufWriter, "%s: %s\r\n", key, value)
		}
	}
	bufWriter.WriteString("\r\n")
	bufWriter.Flush()

	if resp.Body != nil {
		buf := make([]byte, 64*1024) // 64KB buffer
		io.CopyBuffer(clientConn, resp.Body, buf)
	}
}

func (p *LocalProxy) dialTarget(ctx context.Context, host, port, proxyOverride string) (net.Conn, error) {
	targetAddr := net.JoinHostPort(host, port)

	proxyURL := p.tcpProxy
	if proxyOverride != "" {
		proxyURL = proxyOverride
	}

	if proxyURL != "" && proxy.IsSOCKS5URL(proxyURL) {
		socks5Dialer, err := proxy.NewSOCKS5Dialer(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		return socks5Dialer.DialContext(ctx, "tcp", targetAddr)
	}

	if proxyURL != "" && (strings.HasPrefix(proxyURL, "http://") || strings.HasPrefix(proxyURL, "https://")) {
		return p.dialThroughHTTPProxy(ctx, proxyURL, targetAddr)
	}

	dialer := &net.Dialer{
		Timeout:   p.timeout,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, "tcp", targetAddr)
}

func (p *LocalProxy) createProxyClient(proxyURL string) *http.Client {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return p.httpClient // Fallback to default
	}

	transport := &http.Transport{
		Proxy:               http.ProxyURL(parsed),
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
		WriteBufferSize:     64 * 1024,
		ReadBufferSize:      64 * 1024,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (p *LocalProxy) dialThroughHTTPProxy(ctx context.Context, proxyURL, targetAddr string) (net.Conn, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := parsed.Host
	if parsed.Port() == "" {
		if parsed.Scheme == "https" {
			proxyHost = net.JoinHostPort(parsed.Hostname(), "443")
		} else {
			proxyHost = net.JoinHostPort(parsed.Hostname(), "80")
		}
	}

	dialer := &net.Dialer{
		Timeout:   p.timeout,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	if parsed.User != nil {
		username := parsed.User.Username()
		password, _ := parsed.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

func (p *LocalProxy) extractUpstreamProxy(req *http.Request) string {
	proxyAuth := req.Header.Get("Proxy-Authorization")
	if proxyAuth != "" {
		if strings.HasPrefix(proxyAuth, ProxyAuthScheme+" ") {
			proxyURL := strings.TrimPrefix(proxyAuth, ProxyAuthScheme+" ")
			proxyURL = strings.TrimSpace(proxyURL)
			if proxyURL != "" {
				return proxyURL
			}
		}
	}

	return req.Header.Get(HeaderUpstreamProxy)
}

func (p *LocalProxy) extractTLSOnly(req *http.Request) (bool, bool) {
	value := req.Header.Get(HeaderTLSOnly)
	if value == "" {
		return false, false // No override
	}
	return strings.EqualFold(value, "true"), true
}

func (p *LocalProxy) tunnel(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	const bufSize = 64 * 1024 // 64KB

	go func() {
		defer wg.Done()
		buf := make([]byte, bufSize)
		io.CopyBuffer(target, client, buf)
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, bufSize)
		io.CopyBuffer(client, target, buf)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (p *LocalProxy) isPortAllowed(port string) bool {
	blocked := map[string]bool{
		"25": true, "465": true, "587": true, // SMTP
		"23": true, // Telnet
	}
	return !blocked[port]
}

func (p *LocalProxy) sendError(conn net.Conn, status int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(message), message)
	conn.Write([]byte(response))
}

func isHopByHopHeader(header string) bool {
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Proxy-Connection":    true,
		"Te":                  true,
		"Trailer":             true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
	}
	return hopByHop[http.CanonicalHeaderKey(header)]
}
