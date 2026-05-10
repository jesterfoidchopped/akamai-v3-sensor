package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	http "github.com/sardanioss/http"
	tls "github.com/sardanioss/utls"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/dns"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/proxy"
	utls "github.com/sardanioss/utls"
)

type HTTP1Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig
	config   *TransportConfig

	idleConns   map[string][]*http1Conn
	idleConnsMu sync.Mutex

	sessionCache utls.ClientSessionCache

	maxIdleConnsPerHost int
	maxIdleTime         time.Duration
	connectTimeout      time.Duration
	responseTimeout     time.Duration
	insecureSkipVerify  bool
	localAddr           string // Local IP to bind outgoing connections

	stopCleanup chan struct{}
	closed      bool
	closedMu    sync.RWMutex
}

type http1Conn struct {
	host       string
	port       string
	conn       net.Conn
	tlsConn    *utls.UConn
	br         *bufio.Reader
	bw         *bufio.Writer
	createdAt  time.Time
	lastUsedAt time.Time
	useCount   int64
	mu         sync.Mutex
	closed     bool
}

func NewHTTP1Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP1Transport {
	return NewHTTP1TransportWithConfig(preset, dnsCache, nil, nil)
}

func NewHTTP1TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig) *HTTP1Transport {
	return NewHTTP1TransportWithConfig(preset, dnsCache, proxy, nil)
}

func NewHTTP1TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig, config *TransportConfig) *HTTP1Transport {
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h1",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP1Transport{
		preset:              preset,
		dnsCache:            dnsCache,
		proxy:               proxy,
		config:              config,
		idleConns:           make(map[string][]*http1Conn),
		sessionCache:        sessionCache,
		maxIdleConnsPerHost: 6, // Browser-like limit
		maxIdleTime:         90 * time.Second,
		connectTimeout:      30 * time.Second,
		responseTimeout:     60 * time.Second,
		stopCleanup:         make(chan struct{}),
	}

	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	go t.cleanupLoop()

	return t
}

func (t *HTTP1Transport) SetConnectTo(requestHost, connectHost string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

func (t *HTTP1Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

func (t *HTTP1Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
}

func (t *HTTP1Transport) SetLocalAddr(addr string) {
	t.localAddr = addr
}

func (t *HTTP1Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return nil, &TransportError{
			Op:       "roundtrip",
			Host:     req.URL.Hostname(),
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	scheme := req.URL.Scheme

	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	connectHost := t.getConnectHost(host)
	key := fmt.Sprintf("%s://%s:%s", scheme, connectHost, port)

	conn, err := t.getIdleConn(key)
	if err == nil && conn != nil {
		resp, err := t.doRequest(conn, req)
		if err == nil {
			resp.Body = &pooledBodyWrapper{
				body:      resp.Body,
				conn:      conn,
				key:       key,
				transport: t,
				keepAlive: t.shouldKeepAlive(req, resp),
			}
			return resp, nil
		}
		conn.close()
	}

	conn, err = t.createConn(req.Context(), host, port, scheme)
	if err != nil {
		return nil, err
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("request", host, port, "h1", err)
	}

	resp.Body = &pooledBodyWrapper{
		body:      resp.Body,
		conn:      conn,
		key:       key,
		transport: t,
		keepAlive: t.shouldKeepAlive(req, resp),
	}

	return resp, nil
}

func (t *HTTP1Transport) RoundTripWithTLSConn(req *http.Request, tlsConn *utls.UConn, host, port string) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		tlsConn.Close()
		return nil, &TransportError{
			Op:       "roundtrip_with_conn",
			Host:     host,
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	conn := &http1Conn{
		host:       host,
		port:       port,
		conn:       tlsConn,
		tlsConn:    tlsConn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
		br:         bufio.NewReaderSize(tlsConn, 64*1024),  // 64KB read buffer
		bw:         bufio.NewWriterSize(tlsConn, 256*1024), // 256KB write buffer
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("request", host, port, "h1", err)
	}

	resp.Body = &streamBodyWrapper{
		body: resp.Body,
		conn: conn,
	}

	return resp, nil
}

type pooledBodyWrapper struct {
	body      io.ReadCloser
	conn      *http1Conn
	key       string
	transport *HTTP1Transport
	keepAlive bool
	once      sync.Once
}

func (w *pooledBodyWrapper) Read(p []byte) (n int, err error) {
	n, err = w.body.Read(p)
	if err == io.EOF {
		w.handleClose()
	}
	return n, err
}

func (w *pooledBodyWrapper) Close() error {
	err := w.body.Close()
	if err != nil {
		w.once.Do(func() { w.conn.close() })
		return err
	}
	w.handleClose()
	return nil
}

func (w *pooledBodyWrapper) handleClose() {
	w.once.Do(func() {
		w.conn.conn.SetDeadline(time.Time{})
		if w.keepAlive {
			w.transport.putIdleConn(w.key, w.conn)
		} else {
			w.conn.close()
		}
	})
}

type streamBodyWrapper struct {
	body io.ReadCloser
	conn *http1Conn
}

func (w *streamBodyWrapper) Read(p []byte) (n int, err error) {
	return w.body.Read(p)
}

func (w *streamBodyWrapper) Close() error {
	err := w.body.Close()
	w.conn.close()
	return err
}

func (t *HTTP1Transport) StreamRoundTrip(req *http.Request) (*http.Response, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return nil, &TransportError{
			Op:       "stream_roundtrip",
			Host:     req.URL.Hostname(),
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	t.closedMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	scheme := req.URL.Scheme

	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	conn, err := t.createConn(req.Context(), host, port, scheme)
	if err != nil {
		return nil, err
	}

	resp, err := t.doRequest(conn, req)
	if err != nil {
		conn.close()
		return nil, WrapError("stream_request", host, port, "h1", err)
	}

	resp.Body = &streamBodyWrapper{
		body: resp.Body,
		conn: conn,
	}

	return resp, nil
}

func (t *HTTP1Transport) createConn(ctx context.Context, host, port, scheme string) (*http1Conn, error) {
	var rawConn net.Conn
	var err error

	connectHost := t.getConnectHost(host)
	targetAddr := net.JoinHostPort(connectHost, port)

	if t.proxy != nil && t.proxy.URL != "" {
		rawConn, err = t.dialThroughProxy(ctx, connectHost, port)
		if err != nil {
			return nil, NewProxyError("dial_proxy", host, port, err)
		}
	} else {
		ips, err := t.dnsCache.ResolveAllSorted(ctx, connectHost)
		if err != nil {
			return nil, NewDNSError(host, err)
		}
		if len(ips) == 0 {
			return nil, NewDNSError(host, fmt.Errorf("no IP addresses found"))
		}

		dialer := &net.Dialer{
			Timeout:   t.connectTimeout,
			KeepAlive: 30 * time.Second,
		}
		SetDialerControl(dialer, &t.preset.TCPFingerprint)
		ApplyLocalAddrControl(dialer, t.localAddr)
		if t.localAddr != "" {
			localIP := net.ParseIP(t.localAddr)
			dialer.LocalAddr = &net.TCPAddr{IP: localIP}
			if localIP != nil {
				isLocalIPv6 := localIP.To4() == nil
				var filtered []net.IP
				for _, ip := range ips {
					if (ip.To4() == nil) == isLocalIPv6 {
						filtered = append(filtered, ip)
					}
				}
				ips = filtered
				if len(ips) == 0 {
					family := "IPv4"
					if isLocalIPv6 {
						family = "IPv6"
					}
					return nil, NewDNSError(host, fmt.Errorf("no %s addresses found for host (local address is %s)", family, t.localAddr))
				}
			}
		}

		var lastErr error
		for _, ip := range ips {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), port)

			rawConn, err = dialer.DialContext(ctx, network, addr)
			if err == nil {
				break // Connection successful
			}
			lastErr = err
		}

		if rawConn == nil {
			if lastErr != nil {
				return nil, NewConnectionError("dial", host, port, "h1", lastErr)
			}
			return nil, NewConnectionError("dial", host, port, "h1", fmt.Errorf("all connection attempts failed"))
		}
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	conn := &http1Conn{
		host:       host,
		port:       port,
		conn:       rawConn,
		createdAt:  time.Now(),
		lastUsedAt: time.Now(),
	}

	if scheme == "https" {
		var keyLogWriter io.Writer
		if t.config != nil && t.config.KeyLogWriter != nil {
			keyLogWriter = t.config.KeyLogWriter
		} else {
			keyLogWriter = GetKeyLogWriter()
		}

		tlsConfig := &utls.Config{
			ServerName:                         host,
			InsecureSkipVerify:                 t.insecureSkipVerify,
			MinVersion:                         tls.VersionTLS12,
			MaxVersion:                         tls.VersionTLS13,
			NextProtos:                         []string{"http/1.1"}, // Force HTTP/1.1 only
			PreferSkipResumptionOnNilExtension: true,                 // Skip resumption if spec has no PSK extension
			KeyLogWriter:                       keyLogWriter,
		}
		if t.config == nil || t.config.CustomJA3 == "" || fingerprint.JA3HasExtension(t.config.CustomJA3, "41") {
			tlsConfig.ClientSessionCache = t.sessionCache
		}

		var tlsConn *utls.UConn
		if t.config != nil && t.config.CustomJA3 != "" {
			spec, parseErr := fingerprint.ParseJA3(t.config.CustomJA3, t.config.CustomJA3Extras)
			if parseErr != nil {
				rawConn.Close()
				return nil, NewTLSError("parse_ja3", host, port, "h1", parseErr)
			}
			for _, ext := range spec.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					break
				}
			}
			tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
			if err := tlsConn.ApplyPreset(spec); err != nil {
				rawConn.Close()
				return nil, NewTLSError("apply_ja3_preset", host, port, "h1", err)
			}
		} else {
			tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
			tlsConn.SetSessionCache(t.sessionCache)

			if err := tlsConn.BuildHandshakeState(); err != nil {
				rawConn.Close()
				return nil, NewTLSError("build_handshake", host, port, "h1", err)
			}

			for _, ext := range tlsConn.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
					break
				}
			}
		}
		if t.config == nil || t.config.CustomJA3 == "" || fingerprint.JA3HasExtension(t.config.CustomJA3, "41") {
			tlsConn.SetSessionCache(t.sessionCache)
		}

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()

			if IsSpeculativeTLSError(err) && t.proxy != nil && t.proxy.URL != "" {
				MarkProxyNoSpeculative(t.proxy.URL)

				rawConn, dialErr := t.dialHTTPProxyBlockingFresh(ctx, connectHost, port)
				if dialErr != nil {
					return nil, NewTLSError("speculative_fallback_dial", host, port, "h1", dialErr)
				}

				if t.config != nil && t.config.CustomJA3 != "" {
					spec, parseErr := fingerprint.ParseJA3(t.config.CustomJA3, t.config.CustomJA3Extras)
					if parseErr != nil {
						rawConn.Close()
						return nil, NewTLSError("parse_ja3", host, port, "h1", parseErr)
					}
					for _, ext := range spec.Extensions {
						if alpn, ok := ext.(*utls.ALPNExtension); ok {
							alpn.AlpnProtocols = []string{"http/1.1"}
							break
						}
					}
					tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
					if applyErr := tlsConn.ApplyPreset(spec); applyErr != nil {
						rawConn.Close()
						return nil, NewTLSError("apply_ja3_preset", host, port, "h1", applyErr)
					}
				} else {
					tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
					if buildErr := tlsConn.BuildHandshakeState(); buildErr != nil {
						rawConn.Close()
						return nil, NewTLSError("build_handshake", host, port, "h1", buildErr)
					}
					for _, ext := range tlsConn.Extensions {
						if alpn, ok := ext.(*utls.ALPNExtension); ok {
							alpn.AlpnProtocols = []string{"http/1.1"}
							break
						}
					}
				}
				if t.config == nil || t.config.CustomJA3 == "" || fingerprint.JA3HasExtension(t.config.CustomJA3, "41") {
					tlsConn.SetSessionCache(t.sessionCache)
				}
				if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
					rawConn.Close()
					return nil, NewTLSError("tls_handshake", host, port, "h1", hsErr)
				}

				conn.conn = rawConn
			} else {
				return nil, NewTLSError("tls_handshake", host, port, "h1", err)
			}
		}

		conn.tlsConn = tlsConn
		conn.conn = tlsConn
	}

	conn.br = bufio.NewReaderSize(conn.conn, 64*1024)  // 64KB read buffer
	conn.bw = bufio.NewWriterSize(conn.conn, 256*1024) // 256KB write buffer for fast uploads

	_ = targetAddr // suppress unused warning

	return conn, nil
}

func (t *HTTP1Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	if proxy.IsSOCKS5URL(t.proxy.URL) {
		return t.dialThroughSOCKS5(ctx, targetHost, targetPort)
	}

	return t.dialThroughHTTPProxy(ctx, targetHost, targetPort)
}

func (t *HTTP1Transport) dialThroughSOCKS5(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	socks5Dialer, err := proxy.NewSOCKS5Dialer(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}
	if t.localAddr != "" {
		socks5Dialer.SetLocalAddr(t.localAddr)
	}
	socks5Dialer.Control = BuildDialControl(&t.preset.TCPFingerprint, t.localAddr)

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	conn, err := socks5Dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 CONNECT failed: %w", err)
	}

	return conn, nil
}

func (t *HTTP1Transport) dialThroughHTTPProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	proxyURL, err := url.Parse(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if proxyURL.Scheme == "https" {
			proxyPort = "443"
		} else {
			proxyPort = "8080"
		}
	}

	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	SetDialerControl(dialer, &t.preset.TCPFingerprint)
	ApplyLocalAddrControl(dialer, t.localAddr)
	if t.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.localAddr)}
	}

	proxyAddr := net.JoinHostPort(proxyIPs[0], proxyPort)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	proxyAuth := t.getProxyAuth(proxyURL)
	if proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuth)
	}

	connectReq += "Connection: keep-alive\r\n\r\n"

	if t.config != nil && t.config.EnableSpeculativeTLS && !IsProxyNoSpeculative(t.proxy.URL) {
		return NewSpeculativeConn(conn, connectReq), nil
	}

	return t.dialHTTPProxyBlocking(ctx, conn, connectReq)
}

func (t *HTTP1Transport) dialHTTPProxyBlockingFresh(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	proxyURL, err := url.Parse(t.proxy.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := proxyURL.Hostname()
	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if proxyURL.Scheme == "https" {
			proxyPort = "443"
		} else {
			proxyPort = "8080"
		}
	}

	resolver := &net.Resolver{PreferGo: false}
	proxyIPs, err := resolver.LookupHost(ctx, proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve proxy host %s: %w", proxyHost, err)
	}
	if len(proxyIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for proxy host %s", proxyHost)
	}

	dialer := &net.Dialer{
		Timeout:   t.connectTimeout,
		KeepAlive: 30 * time.Second,
	}
	SetDialerControl(dialer, &t.preset.TCPFingerprint)
	ApplyLocalAddrControl(dialer, t.localAddr)
	if t.localAddr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.localAddr)}
	}

	proxyAddr := net.JoinHostPort(proxyIPs[0], proxyPort)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	proxyAuth := t.getProxyAuth(proxyURL)
	if proxyAuth != "" {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", proxyAuth)
	}
	connectReq += "Connection: keep-alive\r\n\r\n"

	return t.dialHTTPProxyBlocking(ctx, conn, connectReq)
}

func (t *HTTP1Transport) dialHTTPProxyBlocking(ctx context.Context, conn net.Conn, connectReq string) (net.Conn, error) {
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetReadDeadline(deadline)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	conn.SetReadDeadline(time.Time{}) // Clear deadline after response
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: io.MultiReader(br, conn)}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (t *HTTP1Transport) getProxyAuth(proxyURL *url.URL) string {
	username := t.proxy.Username
	password := t.proxy.Password

	if proxyURL.User != nil {
		if u := proxyURL.User.Username(); u != "" {
			username = u
		}
		if p, ok := proxyURL.User.Password(); ok {
			password = p
		}
	}

	if username == "" {
		return ""
	}

	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (t *HTTP1Transport) doRequest(conn *http1Conn, req *http.Request) (*http.Response, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.closed {
		return nil, fmt.Errorf("connection closed")
	}

	conn.lastUsedAt = time.Now()
	conn.useCount++

	deadline := time.Now().Add(t.responseTimeout)
	if ctxDeadline, ok := req.Context().Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.conn.SetDeadline(deadline)

	if err := t.writeRequest(conn, req); err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(conn.br, req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (t *HTTP1Transport) writeRequest(conn *http1Conn, req *http.Request) error {
	uri := req.URL.RequestURI()
	if uri == "" {
		uri = "/"
	}
	fmt.Fprintf(conn.bw, "%s %s HTTP/1.1\r\n", req.Method, uri)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(conn.bw, "Host: %s\r\n", host)

	useChunked := req.Body != nil && req.Body != http.NoBody && req.ContentLength <= 0 && req.Header.Get("Content-Length") == ""

	t.writeHeadersInOrder(conn.bw, req, useChunked)

	conn.bw.WriteString("\r\n")

	if err := conn.bw.Flush(); err != nil {
		return err
	}

	if req.Body != nil {
		defer req.Body.Close()
		if useChunked {
			if err := t.writeChunkedBody(conn.bw, req.Body); err != nil {
				return err
			}
		} else {
			_, err := io.Copy(conn.bw, req.Body)
			if err != nil {
				return err
			}
		}
		if err := conn.bw.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func (t *HTTP1Transport) writeChunkedBody(w *bufio.Writer, body io.Reader) error {
	buf := make([]byte, 32*1024) // 32KB chunks
	for {
		n, err := body.Read(buf)
		if n > 0 {
			fmt.Fprintf(w, "%x\r\n", n)
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if _, werr := w.WriteString("\r\n"); werr != nil {
				return werr
			}
			if ferr := w.Flush(); ferr != nil {
				return ferr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if _, err := w.WriteString("0\r\n\r\n"); err != nil {
		return err
	}
	return nil
}

func canonicalHeaderKey(s string) string {
	return textproto.CanonicalMIMEHeaderKey(s)
}

func (t *HTTP1Transport) writeHeadersInOrder(w *bufio.Writer, req *http.Request, useChunked bool) {
	var headerOrder []string
	if customOrder, ok := req.Header[http.HeaderOrderKey]; ok && len(customOrder) > 0 {
		headerOrder = customOrder
	} else {
		headerOrder = []string{
			"Connection",
			"Cache-Control",
			"Upgrade-Insecure-Requests",
			"User-Agent",
			"Accept",
			"Accept-Encoding",
			"Accept-Language",
			"Cookie",
			"Referer",
			"Origin",
			"Sec-Fetch-Dest",
			"Sec-Fetch-Mode",
			"Sec-Fetch-Site",
			"Sec-Fetch-User",
			"Content-Type",
			"Content-Length",
			"Transfer-Encoding",
		}
	}

	written := make(map[string]bool)

	for _, key := range headerOrder {
		canonicalKey := canonicalHeaderKey(key)

		if strings.EqualFold(key, "Content-Length") {
			if useChunked {
				continue
			}
			if values, ok := req.Header[canonicalKey]; ok {
				for _, v := range values {
					fmt.Fprintf(w, "%s: %s\r\n", canonicalKey, v)
				}
				written[canonicalKey] = true
			} else if req.ContentLength > 0 {
				fmt.Fprintf(w, "Content-Length: %d\r\n", req.ContentLength)
				written[canonicalKey] = true
			} else if req.ContentLength == 0 && req.Body != nil && !useChunked {
				fmt.Fprintf(w, "Content-Length: 0\r\n")
				written[canonicalKey] = true
			}
			continue
		}

		if strings.EqualFold(key, "Transfer-Encoding") {
			if useChunked {
				fmt.Fprintf(w, "Transfer-Encoding: chunked\r\n")
				written[canonicalKey] = true
			}
			continue
		}

		if strings.EqualFold(key, "Host") {
			continue
		}

		if values, ok := req.Header[canonicalKey]; ok {
			for _, v := range values {
				fmt.Fprintf(w, "%s: %s\r\n", canonicalKey, v)
			}
			written[canonicalKey] = true
		}
	}

	for key, values := range req.Header {
		if written[key] {
			continue
		}
		if strings.EqualFold(key, "Host") {
			continue
		}
		if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
			continue
		}
		if useChunked && (strings.EqualFold(key, "Transfer-Encoding") || strings.EqualFold(key, "Content-Length")) {
			continue
		}
		for _, v := range values {
			fmt.Fprintf(w, "%s: %s\r\n", key, v)
		}
		written[key] = true
	}

	if !written["Content-Length"] && !useChunked {
		if values, ok := req.Header["Content-Length"]; ok {
			for _, v := range values {
				fmt.Fprintf(w, "Content-Length: %s\r\n", v)
			}
		} else if req.ContentLength > 0 {
			fmt.Fprintf(w, "Content-Length: %d\r\n", req.ContentLength)
		} else if req.ContentLength == 0 && req.Body != nil {
			fmt.Fprintf(w, "Content-Length: 0\r\n")
		}
	}

	if !written["Transfer-Encoding"] && useChunked {
		fmt.Fprintf(w, "Transfer-Encoding: chunked\r\n")
	}

	if _, ok := req.Header["Connection"]; !ok {
		fmt.Fprintf(w, "Connection: keep-alive\r\n")
	}
}

func (t *HTTP1Transport) shouldKeepAlive(req *http.Request, resp *http.Response) bool {
	if strings.EqualFold(resp.Header.Get("Connection"), "close") {
		return false
	}

	if strings.EqualFold(req.Header.Get("Connection"), "close") {
		return false
	}

	if resp.ProtoMajor == 1 && resp.ProtoMinor >= 1 {
		return true
	}

	if strings.ToLower(resp.Header.Get("Connection")) == "keep-alive" {
		return true
	}

	return false
}

func (t *HTTP1Transport) getIdleConn(key string) (*http1Conn, error) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	conns := t.idleConns[key]
	if len(conns) == 0 {
		return nil, nil
	}

	conn := conns[len(conns)-1]
	t.idleConns[key] = conns[:len(conns)-1]

	if time.Since(conn.lastUsedAt) > t.maxIdleTime {
		conn.close()
		return nil, nil
	}

	return conn, nil
}

func (t *HTTP1Transport) putIdleConn(key string, conn *http1Conn) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		conn.close()
		return
	}
	t.closedMu.RUnlock()

	conns := t.idleConns[key]
	if len(conns) >= t.maxIdleConnsPerHost {
		oldConn := conns[0]
		conns = conns[1:]
		go oldConn.close()
	}

	conn.lastUsedAt = time.Now()
	t.idleConns[key] = append(conns, conn)
}

func (c *http1Conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}
	c.closed = true

	if c.tlsConn != nil {
		c.tlsConn.Close()
	} else if c.conn != nil {
		c.conn.Close()
	}
}

func (t *HTTP1Transport) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCleanup:
			return
		case <-ticker.C:
			t.cleanup()
		}
	}
}

func (t *HTTP1Transport) cleanup() {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	for key, conns := range t.idleConns {
		var active []*http1Conn
		for _, conn := range conns {
			if time.Since(conn.lastUsedAt) > t.maxIdleTime {
				go conn.close()
			} else {
				active = append(active, conn)
			}
		}
		if len(active) > 0 {
			t.idleConns[key] = active
		} else {
			delete(t.idleConns, key)
		}
	}
}

func (t *HTTP1Transport) Close() {
	t.closedMu.Lock()
	if t.closed {
		t.closedMu.Unlock()
		return
	}
	t.closed = true
	t.closedMu.Unlock()

	close(t.stopCleanup)

	t.idleConnsMu.Lock()
	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	t.idleConns = nil
	t.idleConnsMu.Unlock()
}

func (t *HTTP1Transport) Refresh() {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return
	}
	t.closedMu.RUnlock()

	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	t.idleConns = make(map[string][]*http1Conn)
}

func (t *HTTP1Transport) SetProxy(proxy *ProxyConfig) {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	for _, conns := range t.idleConns {
		for _, conn := range conns {
			go conn.close()
		}
	}
	t.idleConns = make(map[string][]*http1Conn)

	t.proxy = proxy
}

func (t *HTTP1Transport) GetProxy() *ProxyConfig {
	return t.proxy
}

func (t *HTTP1Transport) GetSessionCache() utls.ClientSessionCache {
	return t.sessionCache
}

func (t *HTTP1Transport) SetSessionCache(cache utls.ClientSessionCache) {
	t.sessionCache = cache
}

func (t *HTTP1Transport) Stats() map[string]HTTP1ConnStats {
	t.idleConnsMu.Lock()
	defer t.idleConnsMu.Unlock()

	stats := make(map[string]HTTP1ConnStats)
	for key, conns := range t.idleConns {
		var totalUseCount int64
		var oldestCreated time.Time
		var newestUsed time.Time

		for _, conn := range conns {
			conn.mu.Lock()
			totalUseCount += conn.useCount
			if oldestCreated.IsZero() || conn.createdAt.Before(oldestCreated) {
				oldestCreated = conn.createdAt
			}
			if conn.lastUsedAt.After(newestUsed) {
				newestUsed = conn.lastUsedAt
			}
			conn.mu.Unlock()
		}

		stats[key] = HTTP1ConnStats{
			IdleConns:      len(conns),
			TotalUseCount:  totalUseCount,
			OldestCreated:  oldestCreated,
			NewestLastUsed: newestUsed,
		}
	}

	return stats
}

type HTTP1ConnStats struct {
	IdleConns      int
	TotalUseCount  int64
	OldestCreated  time.Time
	NewestLastUsed time.Time
}

func (t *HTTP1Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}
