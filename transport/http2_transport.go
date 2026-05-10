package transport

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/dns"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/proxy"
	http "github.com/sardanioss/http"
	"github.com/sardanioss/net/http2"
	"github.com/sardanioss/net/http2/hpack"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

type HTTP2Transport struct {
	preset   *fingerprint.Preset
	dnsCache *dns.Cache
	proxy    *ProxyConfig
	config   *TransportConfig

	conns   map[string]*persistentConn
	connsMu sync.RWMutex

	sessionCache utls.ClientSessionCache

	shuffleSeed int64

	hasPSKSpec bool

	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	insecureSkipVerify bool
	localAddr          string // Local IP to bind outgoing connections

	stopCleanup chan struct{}
	closed      bool
}

type persistentConn struct {
	host           string
	tlsConn        *utls.UConn
	h2Conn         *http2.ClientConn
	createdAt      time.Time
	lastUsedAt     time.Time
	useCount       int64
	inFlight       int32 // number of active RoundTrip calls — prevents cleanup during long requests
	sessionResumed bool  // True if TLS session was resumed (faster handshake)
	tlsVersion     uint16
	cipherSuite    uint16
	mu             sync.Mutex
}

func NewHTTP2Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) *HTTP2Transport {
	return NewHTTP2TransportWithProxy(preset, dnsCache, nil)
}

func NewHTTP2TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig) *HTTP2Transport {
	return NewHTTP2TransportWithConfig(preset, dnsCache, proxy, nil)
}

func NewHTTP2TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxy *ProxyConfig, config *TransportConfig) *HTTP2Transport {
	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h2",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	hasPSKSpec := preset.PSKClientHelloID.Client != ""
	if !hasPSKSpec && config != nil && config.CustomJA3 != "" {
		hasPSKSpec = fingerprint.JA3HasExtension(config.CustomJA3, "41")
	}
	if !hasPSKSpec && preset.JA3 != "" {
		hasPSKSpec = fingerprint.JA3HasExtension(preset.JA3, "41")
	}

	t := &HTTP2Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		proxy:          proxy,
		config:         config,
		conns:          make(map[string]*persistentConn),
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		hasPSKSpec:     hasPSKSpec,
		maxIdleTime:    90 * time.Second,
		maxConnAge:     5 * time.Minute,
		connectTimeout: 30 * time.Second,
		stopCleanup:    make(chan struct{}),
	}

	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	go t.cleanupLoop()

	return t
}

func (t *HTTP2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.connsMu.RLock()
	if t.closed {
		t.connsMu.RUnlock()
		return nil, fmt.Errorf("http2: transport closed")
	}
	t.connsMu.RUnlock()

	host := req.URL.Hostname()
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	connectHost := t.getConnectHost(host)
	key := net.JoinHostPort(connectHost, port)

	conn, err := t.getOrCreateConn(req.Context(), host, port, key)
	if err != nil {
		return nil, err
	}

	conn.mu.Lock()
	conn.lastUsedAt = time.Now()
	conn.inFlight++
	conn.mu.Unlock()

	resp, err := conn.h2Conn.RoundTrip(req)
	if err != nil {
		conn.mu.Lock()
		conn.inFlight--
		conn.mu.Unlock()

		t.removeConn(key)

		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}

		conn, err = t.getOrCreateConn(req.Context(), host, port, key)
		if err != nil {
			return nil, err
		}

		conn.mu.Lock()
		conn.inFlight++
		conn.mu.Unlock()

		resp, err = conn.h2Conn.RoundTrip(req)
		if err != nil {
			conn.mu.Lock()
			conn.inFlight--
			conn.mu.Unlock()
			t.removeConn(key)
			return nil, err
		}
	}

	conn.mu.Lock()
	conn.lastUsedAt = time.Now()
	conn.inFlight--
	conn.useCount++
	conn.mu.Unlock()

	return resp, nil
}

func (t *HTTP2Transport) getOrCreateConn(ctx context.Context, host, port, key string) (*persistentConn, error) {
	t.connsMu.RLock()
	if t.closed {
		t.connsMu.RUnlock()
		return nil, fmt.Errorf("http2: transport closed")
	}
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if exists && t.isConnUsable(conn) {
		return conn, nil
	}

	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		return nil, fmt.Errorf("http2: transport closed")
	}

	if conn, exists = t.conns[key]; exists && t.isConnUsable(conn) {
		t.connsMu.Unlock()
		return conn, nil
	}

	if exists {
		go conn.close()
		delete(t.conns, key)
	}
	t.connsMu.Unlock()

	newConn, err := t.createConn(ctx, host, port)
	if err != nil {
		return nil, err
	}

	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		go newConn.close()
		return nil, fmt.Errorf("http2: transport closed")
	}
	if existingConn, ok := t.conns[key]; ok && t.isConnUsable(existingConn) {
		t.connsMu.Unlock()
		go newConn.close()
		return existingConn, nil
	}
	t.conns[key] = newConn
	t.connsMu.Unlock()

	return newConn, nil
}

func (t *HTTP2Transport) isConnUsable(conn *persistentConn) bool {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if time.Since(conn.createdAt) > t.maxConnAge {
		return false
	}

	if conn.inFlight == 0 && time.Since(conn.lastUsedAt) > t.maxIdleTime {
		return false
	}

	if conn.h2Conn == nil {
		return false
	}

	return true
}

func (t *HTTP2Transport) createConn(ctx context.Context, host, port string) (*persistentConn, error) {
	var rawConn net.Conn
	var err error

	connectHost := t.getConnectHost(host)

	targetAddr := net.JoinHostPort(host, port)

	if t.proxy != nil && t.proxy.URL != "" {
		rawConn, err = t.dialThroughProxy(ctx, connectHost, port)
		if err != nil {
			return nil, fmt.Errorf("proxy connection failed: %w", err)
		}
	} else {
		ips, err := t.dnsCache.ResolveAllSorted(ctx, connectHost)
		if err != nil {
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("DNS resolution failed: no IP addresses found")
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
					return nil, fmt.Errorf("no %s addresses found for host (local address is %s)", family, t.localAddr)
				}
			}
		}

		var lastErr error
		remaining := len(ips)
		for _, ip := range ips {
			network := "tcp4"
			if ip.To4() == nil {
				network = "tcp6"
			}
			addr := net.JoinHostPort(ip.String(), port)

			perAddr := t.connectTimeout / time.Duration(remaining)
			if perAddr > 10*time.Second {
				perAddr = 10 * time.Second
			}
			dialCtx, dialCancel := context.WithTimeout(ctx, perAddr)
			rawConn, err = dialer.DialContext(dialCtx, network, addr)
			dialCancel()
			if err == nil {
				break // Connection successful
			}
			lastErr = err
			remaining--
		}

		if rawConn == nil {
			if lastErr != nil {
				return nil, fmt.Errorf("TCP connect failed: %w", lastErr)
			}
			return nil, fmt.Errorf("TCP connect failed: all connection attempts failed")
		}
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	var specToUse *utls.ClientHelloSpec
	ja3String := ""
	var ja3Extras *fingerprint.JA3Extras
	if t.config != nil && t.config.CustomJA3 != "" {
		ja3String = t.config.CustomJA3
		ja3Extras = t.config.CustomJA3Extras
	} else if t.preset.JA3 != "" {
		ja3String = t.preset.JA3
		ja3Extras = t.preset.JA3Extras
	}
	if ja3String != "" {
		spec, parseErr := fingerprint.ParseJA3(ja3String, ja3Extras)
		if parseErr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to parse JA3: %w", parseErr)
		}
		specToUse = spec
	} else if t.hasPSKSpec {
		if spec, err := utls.UTLSIdToSpecWithSeed(t.preset.PSKClientHelloID, t.shuffleSeed); err == nil {
			specToUse = &spec
		}
	}
	if specToUse == nil {
		if spec, err := utls.UTLSIdToSpecWithSeed(t.preset.ClientHelloID, t.shuffleSeed); err == nil {
			specToUse = &spec
		}
	}

	var echConfigList []byte
	if t.config != nil {
		if len(t.config.ECHConfig) > 0 {
			echConfigList = t.config.ECHConfig
		} else if t.config.ECHConfigDomain != "" {
			echConfigList, _ = dns.FetchECHConfigs(ctx, t.config.ECHConfigDomain)
		}
	}

	minVersion := uint16(tls.VersionTLS12)
	if len(echConfigList) > 0 {
		minVersion = tls.VersionTLS13
	}

	var keyLogWriter io.Writer
	if t.config != nil && t.config.KeyLogWriter != nil {
		keyLogWriter = t.config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	tlsConfig := &utls.Config{
		ServerName:                         host,
		InsecureSkipVerify:                 t.insecureSkipVerify,
		MinVersion:                         minVersion,
		MaxVersion:                         tls.VersionTLS13,
		OmitEmptyPsk:                       true,          // Chrome doesn't send empty PSK on first connection
		PreferSkipResumptionOnNilExtension: true,          // Skip resumption if spec has no PSK extension instead of panicking
		EncryptedClientHelloConfigList:     echConfigList, // ECH configuration (if available)
		KeyLogWriter:                       keyLogWriter,
	}

	if t.hasPSKSpec {
		tlsConfig.ClientSessionCache = t.sessionCache
	}

	var tlsConn *utls.UConn
	if specToUse != nil {
		tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(specToUse); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply TLS preset: %w", err)
		}
	} else {
		tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
	}

	if t.hasPSKSpec {
		tlsConn.SetSessionCache(t.sessionCache)
	}

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()

		if IsSpeculativeTLSError(err) && t.proxy != nil && t.proxy.URL != "" {
			MarkProxyNoSpeculative(t.proxy.URL)

			rawConn, dialErr := t.dialHTTPProxyBlockingFresh(ctx, connectHost, port)
			if dialErr != nil {
				return nil, fmt.Errorf("speculative TLS fallback dial failed: %w", dialErr)
			}

			var fallbackSpec *utls.ClientHelloSpec
			fallbackJA3 := ""
			var fallbackJA3Extras *fingerprint.JA3Extras
			if t.config != nil && t.config.CustomJA3 != "" {
				fallbackJA3 = t.config.CustomJA3
				fallbackJA3Extras = t.config.CustomJA3Extras
			} else if t.preset.JA3 != "" {
				fallbackJA3 = t.preset.JA3
				fallbackJA3Extras = t.preset.JA3Extras
			}
			if fallbackJA3 != "" {
				spec, parseErr := fingerprint.ParseJA3(fallbackJA3, fallbackJA3Extras)
				if parseErr != nil {
					rawConn.Close()
					return nil, fmt.Errorf("speculative TLS fallback: failed to parse JA3: %w", parseErr)
				}
				fallbackSpec = spec
			} else if t.hasPSKSpec {
				if spec, specErr := utls.UTLSIdToSpecWithSeed(t.preset.PSKClientHelloID, t.shuffleSeed); specErr == nil {
					fallbackSpec = &spec
				}
			}
			if fallbackSpec == nil {
				if spec, specErr := utls.UTLSIdToSpecWithSeed(t.preset.ClientHelloID, t.shuffleSeed); specErr == nil {
					fallbackSpec = &spec
				}
			}

			if fallbackSpec != nil {
				tlsConn = utls.UClient(rawConn, tlsConfig, utls.HelloCustom)
				if applyErr := tlsConn.ApplyPreset(fallbackSpec); applyErr != nil {
					rawConn.Close()
					return nil, fmt.Errorf("speculative TLS fallback preset failed: %w", applyErr)
				}
			} else {
				tlsConn = utls.UClient(rawConn, tlsConfig, t.preset.ClientHelloID)
			}
			if t.hasPSKSpec {
				tlsConn.SetSessionCache(t.sessionCache)
			}

			if hsErr := tlsConn.HandshakeContext(ctx); hsErr != nil {
				rawConn.Close()
				return nil, fmt.Errorf("TLS handshake failed (after speculative fallback): %w", hsErr)
			}
			goto alpnCheck
		}

		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

alpnCheck:
	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		return nil, &ALPNMismatchError{
			Expected:   "h2",
			Negotiated: state.NegotiatedProtocol,
			TLSConn:    tlsConn,
			Host:       host,
			Port:       port,
		}
	}

	settings := t.preset.HTTP2Settings

	tlsOnly := t.config != nil && t.config.TLSOnly
	userAgent := t.preset.UserAgent
	if tlsOnly {
		userAgent = "" // Don't set default User-Agent in TLS-only mode
	}

	h2Settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:   settings.HeaderTableSize,
		http2.SettingEnablePush:        boolToUint32(settings.EnablePush),
		http2.SettingInitialWindowSize: settings.InitialWindowSize,
		http2.SettingMaxHeaderListSize: settings.MaxHeaderListSize,
	}
	var h2SettingsOrder []http2.SettingID
	if order := t.preset.H2SettingsOrder(); order != nil {
		h2SettingsOrder = uint16sToSettingIDs(order)
	} else {
		if settings.NoRFC7540Priorities {
			h2SettingsOrder = []http2.SettingID{
				http2.SettingEnablePush,
				http2.SettingInitialWindowSize,
			}
		} else {
			h2SettingsOrder = []http2.SettingID{
				http2.SettingHeaderTableSize,
				http2.SettingEnablePush,
				http2.SettingInitialWindowSize,
				http2.SettingMaxHeaderListSize,
			}
		}
		if settings.MaxConcurrentStreams > 0 {
			h2SettingsOrder = append(h2SettingsOrder, http2.SettingMaxConcurrentStreams)
		}
		if settings.MaxFrameSize > 0 {
			h2SettingsOrder = append(h2SettingsOrder, http2.SettingMaxFrameSize)
		}
		if settings.NoRFC7540Priorities {
			h2SettingsOrder = append(h2SettingsOrder, http2.SettingNoRFC7540Priorities)
		}
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

	pseudoOrder := []string{":method", ":authority", ":scheme", ":path"} // Chrome default
	if t.config != nil && len(t.config.CustomPseudoOrder) > 0 {
		pseudoOrder = t.config.CustomPseudoOrder
	} else if order := t.preset.H2PseudoHeaderOrder(); order != nil {
		pseudoOrder = order
	} else if settings.NoRFC7540Priorities {
		pseudoOrder = []string{":method", ":scheme", ":path", ":authority"} // Safari order
	}

	h2Transport := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         tlsOnly, // Disable auto Accept-Encoding in TLS-only mode
		StrictMaxConcurrentStreams: false,
		MaxHeaderListSize:          settings.MaxHeaderListSize,
		MaxReadFrameSize:           settings.MaxFrameSize,
		MaxDecoderHeaderTableSize:  settings.HeaderTableSize,
		MaxEncoderHeaderTableSize:  settings.HeaderTableSize,
		ReadIdleTimeout:            t.maxIdleTime,
		PingTimeout:                15 * time.Second,

		ConnectionFlow:     settings.ConnectionWindowUpdate,
		Settings:           h2Settings,
		SettingsOrder:      h2SettingsOrder,
		DisableCookieSplit: t.preset.H2DisableCookieSplit(),
		PseudoHeaderOrder:  pseudoOrder,
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
		HeaderPriorityFunc: func() func(req *http.Request) *http2.PriorityParam {
			preset := t.preset
			if !preset.H2HasPriorityTable() {
				return nil
			}
			return func(req *http.Request) *http2.PriorityParam {
				dest := req.Header.Get("Sec-Fetch-Dest")
				weight, exclusive, _, ok := preset.H2PriorityFor(dest)
				if !ok {
					return nil // fall back to HeaderPriority static default
				}
				return &http2.PriorityParam{
					Weight:    uint8(weight - 1), // wire format is weight-1; weight is 1..256, never 0
					Exclusive: exclusive,
					StreamDep: 0,
				}
			}
		}(),
		HeaderOrder:         t.preset.H2HeaderOrder(),
		UserAgent:           userAgent,
		StreamPriorityMode:  resolveStreamPriorityMode(t.preset.H2StreamPriorityMode()),
		HPACKIndexingPolicy: resolveHPACKIndexingPolicy(t.preset.H2HPACKIndexingPolicy()),
		HPACKNeverIndex:     t.preset.H2HPACKNeverIndex(),
	}

	h2Conn, err := h2Transport.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}

	_ = targetAddr // Used in proxy connection

	connState := tlsConn.ConnectionState()
	sessionResumed := connState.DidResume

	return &persistentConn{
		host:           host,
		tlsConn:        tlsConn,
		h2Conn:         h2Conn,
		createdAt:      time.Now(),
		lastUsedAt:     time.Now(),
		useCount:       0,
		sessionResumed: sessionResumed,
		tlsVersion:     connState.Version,
		cipherSuite:    connState.CipherSuite,
	}, nil
}

func (t *HTTP2Transport) dialThroughProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
	if proxy.IsSOCKS5URL(t.proxy.URL) {
		return t.dialThroughSOCKS5(ctx, targetHost, targetPort)
	}

	return t.dialThroughHTTPProxy(ctx, targetHost, targetPort)
}

func (t *HTTP2Transport) dialThroughSOCKS5(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
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

func (t *HTTP2Transport) dialThroughHTTPProxy(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
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

func (t *HTTP2Transport) dialHTTPProxyBlockingFresh(ctx context.Context, targetHost, targetPort string) (net.Conn, error) {
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

func (t *HTTP2Transport) dialHTTPProxyBlocking(ctx context.Context, conn net.Conn, connectReq string) (net.Conn, error) {
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetReadDeadline(deadline)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	conn.SetReadDeadline(time.Time{}) // Clear deadline after response
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: io.MultiReader(reader, conn)}, nil
	}
	return conn, nil
}

func (t *HTTP2Transport) getProxyAuth(proxyURL *url.URL) string {
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

func (t *HTTP2Transport) removeConn(key string) {
	t.connsMu.Lock()
	conn, exists := t.conns[key]
	if exists {
		delete(t.conns, key)
	}
	t.connsMu.Unlock()

	if exists && conn != nil {
		go conn.close()
	}
}

func (c *persistentConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.h2Conn != nil {
		c.h2Conn.Close()
	}
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
}

func (t *HTTP2Transport) cleanupLoop() {
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

func (t *HTTP2Transport) cleanup() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	for key, conn := range t.conns {
		if !t.isConnUsable(conn) {
			delete(t.conns, key)
			go conn.close()
		}
	}
}

func (t *HTTP2Transport) Close() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.closed {
		return
	}
	t.closed = true

	close(t.stopCleanup)

	for _, conn := range t.conns {
		go conn.close()
	}
	t.conns = nil
}

func (t *HTTP2Transport) Refresh() {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.closed {
		return
	}

	for _, conn := range t.conns {
		go conn.close()
	}
	t.conns = make(map[string]*persistentConn)
}

func (t *HTTP2Transport) GetSessionCache() utls.ClientSessionCache {
	return t.sessionCache
}

func (t *HTTP2Transport) SetSessionCache(cache utls.ClientSessionCache) {
	t.sessionCache = cache
}

func (t *HTTP2Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
}

func (t *HTTP2Transport) SetLocalAddr(addr string) {
	t.localAddr = addr
}

func (t *HTTP2Transport) Stats() map[string]ConnStats {
	t.connsMu.RLock()
	defer t.connsMu.RUnlock()

	stats := make(map[string]ConnStats)
	for key, conn := range t.conns {
		conn.mu.Lock()
		stats[key] = ConnStats{
			Host:           conn.host,
			CreatedAt:      conn.createdAt,
			LastUsedAt:     conn.lastUsedAt,
			UseCount:       conn.useCount,
			Age:            time.Since(conn.createdAt),
			IdleTime:       time.Since(conn.lastUsedAt),
			IsReused:       conn.useCount > 1,
			SessionResumed: conn.sessionResumed,
			TLSVersion:     conn.tlsVersion,
			CipherSuite:    conn.cipherSuite,
		}
		conn.mu.Unlock()
	}

	return stats
}

func (t *HTTP2Transport) IsConnectionReused(host, port string) bool {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if !exists {
		return false
	}
	return t.isConnUsable(conn)
}

func (t *HTTP2Transport) GetConnectionUseCount(host, port string) int64 {
	key := net.JoinHostPort(host, port)
	t.connsMu.RLock()
	conn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if !exists {
		return 0
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.useCount
}

type ConnStats struct {
	Host           string
	CreatedAt      time.Time
	LastUsedAt     time.Time
	UseCount       int64
	Age            time.Duration
	IdleTime       time.Duration
	IsReused       bool
	SessionResumed bool   // True if TLS session was resumed
	TLSVersion     uint16 // TLS version (e.g., 0x0304 for TLS 1.3)
	CipherSuite    uint16 // Negotiated cipher suite
}

func (t *HTTP2Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

func (t *HTTP2Transport) SetConnectTo(requestHost, connectHost string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

func (t *HTTP2Transport) SetECHConfigDomain(domain string) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain
}

func (t *HTTP2Transport) SetECHConfig(echConfig []byte) {
	t.connsMu.Lock()
	defer t.connsMu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig
}

func (t *HTTP2Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

func (t *HTTP2Transport) Connect(ctx context.Context, host, port string) error {
	connectHost := t.getConnectHost(host)
	key := net.JoinHostPort(connectHost, port)

	t.connsMu.RLock()
	if t.closed {
		t.connsMu.RUnlock()
		return fmt.Errorf("http2: transport closed")
	}
	existingConn, exists := t.conns[key]
	t.connsMu.RUnlock()

	if exists && t.isConnUsable(existingConn) {
		return nil // Already connected
	}

	conn, err := t.createConn(ctx, host, port)
	if err != nil {
		return err
	}

	t.connsMu.Lock()
	if t.closed {
		t.connsMu.Unlock()
		go conn.close()
		return fmt.Errorf("http2: transport closed")
	}
	if oldConn, exists := t.conns[key]; exists {
		if !t.isConnUsable(oldConn) {
			go oldConn.close()
		} else {
			go conn.close()
			t.connsMu.Unlock()
			return nil
		}
	}
	t.conns[key] = conn
	t.connsMu.Unlock()

	return nil
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
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
