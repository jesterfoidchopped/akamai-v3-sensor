package transport

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	http "github.com/sardanioss/http"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/jesterfoidchopped/akamai-v3-sensor/dns"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/klauspost/compress/zstd"
)

type Protocol int

const (
	ProtocolAuto Protocol = iota
	ProtocolHTTP1
	ProtocolHTTP2
	ProtocolHTTP3
)

var (
	bodyPool1MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 1*1024*1024)
			return &buf
		},
	}
	bodyPool10MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 10*1024*1024)
			return &buf
		},
	}
	bodyPool100MB = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 100*1024*1024)
			return &buf
		},
	}
)

func getPooledBuffer(size int64) (*[]byte, func()) {
	if size <= 1*1024*1024 {
		buf := bodyPool1MB.Get().(*[]byte)
		return buf, func() { bodyPool1MB.Put(buf) }
	}
	if size <= 10*1024*1024 {
		buf := bodyPool10MB.Get().(*[]byte)
		return buf, func() { bodyPool10MB.Put(buf) }
	}
	if size <= 100*1024*1024 {
		buf := bodyPool100MB.Get().(*[]byte)
		return buf, func() { bodyPool100MB.Put(buf) }
	}
	buf := make([]byte, size)
	return &buf, func() {} // No-op release for non-pooled buffers
}

func (p Protocol) String() string {
	switch p {
	case ProtocolAuto:
		return "auto"
	case ProtocolHTTP1:
		return "h1"
	case ProtocolHTTP2:
		return "h2"
	case ProtocolHTTP3:
		return "h3"
	default:
		return "unknown"
	}
}

type ProxyConfig struct {
	URL      string // Proxy URL (e.g., "http://proxy:8080" or "http://user:pass@proxy:8080")
	Username string // Proxy username (optional, can also be in URL)
	Password string // Proxy password (optional, can also be in URL)

	TCPProxy string

	UDPProxy string
}

type TransportConfig struct {
	ConnectTo map[string]string

	ECHConfig []byte

	ECHConfigDomain string

	TLSOnly bool

	QuicIdleTimeout time.Duration

	LocalAddr string

	SessionCacheBackend SessionCacheBackend

	SessionCacheErrorCallback ErrorCallback

	KeyLogWriter io.Writer

	EnableSpeculativeTLS bool

	CustomJA3 string

	CustomJA3Extras *fingerprint.JA3Extras

	CustomH2Settings *fingerprint.HTTP2Settings

	CustomPseudoOrder []string

	CustomTCPFingerprint *fingerprint.TCPFingerprint
}

type Request struct {
	Method     string
	URL        string
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       []byte
	BodyReader io.Reader // For streaming uploads - used instead of Body if set
	Timeout    time.Duration

	TLSOnly *bool
}

type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string][]string // Multi-value headers
}

type Response struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       io.ReadCloser       // Streaming body - call Close() when done
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h1", "h2", or "h3"
	History    []*RedirectInfo

	bodyBytes []byte
	bodyRead  bool
}

func (r *Response) Close() error {
	if r.Body != nil {
		return r.Body.Close()
	}
	return nil
}

func (r *Response) GetHeader(key string) string {
	if values := r.Headers[strings.ToLower(key)]; len(values) > 0 {
		return values[0]
	}
	return ""
}

func (r *Response) GetHeaders(key string) []string {
	return r.Headers[strings.ToLower(key)]
}

func (r *Response) Bytes() ([]byte, error) {
	if r.bodyRead {
		return r.bodyBytes, nil
	}
	if r.Body == nil {
		return nil, nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.bodyBytes = data
	r.bodyRead = true
	return data, nil
}

func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
}

type Transport struct {
	h1Transport *HTTP1Transport
	h2Transport *HTTP2Transport
	h3Transport *HTTP3Transport
	dnsCache    *dns.Cache
	preset      *fingerprint.Preset
	timeout     time.Duration
	protocol    Protocol
	proxy       *ProxyConfig
	config      *TransportConfig

	protocolSupport   map[string]Protocol // Best known protocol per host
	protocolSupportMu sync.RWMutex

	insecureSkipVerify bool

	h3ProxyError error

	customHeaderOrder   []string
	customHeaderOrderMu sync.RWMutex

	customPseudoOrder []string

	tlsOnly bool
}

func NewTransport(presetName string) *Transport {
	return NewTransportWithConfig(presetName, nil, nil)
}

func NewTransportWithProxy(presetName string, proxy *ProxyConfig) *Transport {
	return NewTransportWithConfig(presetName, proxy, nil)
}

func NewTransportWithConfig(presetName string, proxy *ProxyConfig, config *TransportConfig) *Transport {
	preset := fingerprint.Get(presetName)
	dnsCache := dns.NewCache()

	tlsOnly := false
	if config != nil {
		tlsOnly = config.TLSOnly

		if config.CustomH2Settings != nil {
			preset.HTTP2Settings = *config.CustomH2Settings
		}
		if config.CustomTCPFingerprint != nil {
			fp := config.CustomTCPFingerprint
			if fp.TTL > 0 {
				preset.TCPFingerprint.TTL = fp.TTL
			}
			if fp.MSS > 0 {
				preset.TCPFingerprint.MSS = fp.MSS
			}
			if fp.WindowSize > 0 {
				preset.TCPFingerprint.WindowSize = fp.WindowSize
			}
			if fp.WindowScale > 0 {
				preset.TCPFingerprint.WindowScale = fp.WindowScale
			}
			if fp.DFBit {
				preset.TCPFingerprint.DFBit = fp.DFBit
			}
		}
	}

	var customPseudoOrder []string
	if config != nil && len(config.CustomPseudoOrder) > 0 {
		customPseudoOrder = config.CustomPseudoOrder
	}

	t := &Transport{
		dnsCache:          dnsCache,
		preset:            preset,
		timeout:           30 * time.Second,
		protocol:          ProtocolAuto,
		protocolSupport:   make(map[string]Protocol),
		proxy:             proxy,
		config:            config,
		customPseudoOrder: customPseudoOrder,
		tlsOnly:           tlsOnly,
	}

	var tcpProxyURL, udpProxyURL string
	if proxy != nil {
		tcpProxyURL = proxy.TCPProxy
		if tcpProxyURL == "" {
			tcpProxyURL = proxy.URL
		}
		udpProxyURL = proxy.UDPProxy
		if udpProxyURL == "" {
			udpProxyURL = proxy.URL
		}
	}

	var tcpProxy *ProxyConfig
	if tcpProxyURL != "" {
		tcpProxy = &ProxyConfig{URL: tcpProxyURL}
	}

	t.h1Transport = NewHTTP1TransportWithConfig(preset, dnsCache, tcpProxy, config)
	t.h2Transport = NewHTTP2TransportWithConfig(preset, dnsCache, tcpProxy, config)

	if udpProxyURL != "" {
		udpProxy := &ProxyConfig{URL: udpProxyURL}
		if isSOCKS5Proxy(udpProxyURL) {
			h3Transport, err := NewHTTP3TransportWithConfig(preset, dnsCache, udpProxy, config)
			if err != nil {
				t.h3ProxyError = fmt.Errorf("SOCKS5 UDP proxy initialization failed: %w", err)
				t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(udpProxyURL) {
			h3Transport, err := NewHTTP3TransportWithMASQUE(preset, dnsCache, udpProxy, config)
			if err != nil {
				t.h3ProxyError = fmt.Errorf("MASQUE proxy initialization failed: %w", err)
				t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			t.h3ProxyError = fmt.Errorf("HTTP proxy does not support HTTP/3 (QUIC requires UDP)")
			t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
		}
	} else {
		t.h3Transport, _ = NewHTTP3TransportWithTransportConfig(preset, dnsCache, config)
	}

	return t
}

func (t *Transport) SetProtocol(p Protocol) {
	t.protocol = p
}

func (t *Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
	t.h1Transport.SetInsecureSkipVerify(skip)
	if t.h2Transport != nil {
		t.h2Transport.SetInsecureSkipVerify(skip)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetInsecureSkipVerify(skip)
	}
}

func (t *Transport) SetDisableECH(disable bool) {
	if t.h3Transport != nil {
		t.h3Transport.SetDisableECH(disable)
	}
}

func (t *Transport) SetProxy(proxy *ProxyConfig) {
	t.proxy = proxy
	t.h3ProxyError = nil // Clear stale error from previous proxy config

	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()

	tcpProxy := proxy
	if proxy != nil && proxy.TCPProxy != "" {
		tcpProxy = &ProxyConfig{URL: proxy.TCPProxy}
	}
	t.h1Transport = NewHTTP1TransportWithConfig(t.preset, t.dnsCache, tcpProxy, t.config)
	t.h2Transport = NewHTTP2TransportWithConfig(t.preset, t.dnsCache, tcpProxy, t.config)

	udpProxyURL := ""
	if proxy != nil {
		if proxy.UDPProxy != "" {
			udpProxyURL = proxy.UDPProxy
		} else if proxy.URL != "" {
			udpProxyURL = proxy.URL
		}
	}

	if udpProxyURL != "" {
		if isSOCKS5Proxy(udpProxyURL) {
			h3Proxy := &ProxyConfig{URL: udpProxyURL}
			h3Transport, err := NewHTTP3TransportWithProxy(t.preset, t.dnsCache, h3Proxy)
			if err != nil {
				t.h3ProxyError = fmt.Errorf("SOCKS5 UDP proxy initialization failed: %w", err)
				t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(udpProxyURL) {
			h3Proxy := &ProxyConfig{URL: udpProxyURL}
			h3Transport, err := NewHTTP3TransportWithMASQUE(t.preset, t.dnsCache, h3Proxy, nil)
			if err != nil {
				t.h3ProxyError = fmt.Errorf("MASQUE proxy initialization failed: %w", err)
				t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			t.h3ProxyError = fmt.Errorf("HTTP proxy does not support HTTP/3 (QUIC requires UDP)")
			t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
		}
	} else {
		t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
	}

	if t.insecureSkipVerify {
		t.h1Transport.SetInsecureSkipVerify(true)
		t.h2Transport.SetInsecureSkipVerify(true)
		if t.h3Transport != nil {
			t.h3Transport.SetInsecureSkipVerify(true)
		}
	}
}

func (t *Transport) SetPreset(presetName string) {
	t.preset = fingerprint.Get(presetName)

	if t.config != nil && t.config.CustomH2Settings != nil {
		t.preset.HTTP2Settings = *t.config.CustomH2Settings
	}

	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()

	var tcpProxy *ProxyConfig
	if t.proxy != nil {
		if t.proxy.TCPProxy != "" {
			tcpProxy = &ProxyConfig{URL: t.proxy.TCPProxy}
		} else {
			tcpProxy = t.proxy
		}
	}
	t.h1Transport = NewHTTP1TransportWithConfig(t.preset, t.dnsCache, tcpProxy, t.config)
	t.h2Transport = NewHTTP2TransportWithConfig(t.preset, t.dnsCache, tcpProxy, t.config)

	if t.proxy != nil && t.proxy.URL != "" {
		if isSOCKS5Proxy(t.proxy.URL) {
			h3Transport, err := NewHTTP3TransportWithProxy(t.preset, t.dnsCache, t.proxy)
			if err != nil {
				t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else if isMASQUEProxy(t.proxy.URL) {
			h3Transport, err := NewHTTP3TransportWithMASQUE(t.preset, t.dnsCache, t.proxy, nil)
			if err != nil {
				t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
			} else {
				t.h3Transport = h3Transport
			}
		} else {
			t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
		}
	} else {
		t.h3Transport, _ = NewHTTP3Transport(t.preset, t.dnsCache)
	}

	if t.insecureSkipVerify {
		t.h1Transport.SetInsecureSkipVerify(true)
		t.h2Transport.SetInsecureSkipVerify(true)
		if t.h3Transport != nil {
			t.h3Transport.SetInsecureSkipVerify(true)
		}
	}
}

func isSOCKS5Proxy(proxyURL string) bool {
	return IsSOCKS5Proxy(proxyURL)
}

func IsSOCKS5Proxy(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}
	return parsed.Scheme == "socks5" || parsed.Scheme == "socks5h"
}

func isMASQUEProxy(proxyURL string) bool {
	return IsMASQUEProxy(proxyURL)
}

func IsMASQUEProxy(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	if parsed.Scheme == "masque" {
		return true
	}

	if parsed.Scheme == "https" {
		path := strings.ToLower(parsed.Path)
		if strings.Contains(path, "masque") || strings.Contains(path, "connect-udp") {
			return true
		}
	}

	return false
}

func SupportsQUIC(proxyURL string) bool {
	return IsSOCKS5Proxy(proxyURL) || IsMASQUEProxy(proxyURL)
}

func (t *Transport) SetTimeout(timeout time.Duration) {
	t.timeout = timeout
}

func (t *Transport) SetConnectTo(requestHost, connectHost string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost

	if t.h1Transport != nil {
		t.h1Transport.SetConnectTo(requestHost, connectHost)
	}
	if t.h2Transport != nil {
		t.h2Transport.SetConnectTo(requestHost, connectHost)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetConnectTo(requestHost, connectHost)
	}
}

func (t *Transport) SetECHConfig(echConfig []byte) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig

	if t.h2Transport != nil {
		t.h2Transport.SetECHConfig(echConfig)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetECHConfig(echConfig)
	}
}

func (t *Transport) SetECHConfigDomain(domain string) {
	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain

	if t.h2Transport != nil {
		t.h2Transport.SetECHConfigDomain(domain)
	}
	if t.h3Transport != nil {
		t.h3Transport.SetECHConfigDomain(domain)
	}
}

func (t *Transport) SetHeaderOrder(order []string) {
	t.customHeaderOrderMu.Lock()
	defer t.customHeaderOrderMu.Unlock()

	if len(order) == 0 {
		t.customHeaderOrder = nil
		return
	}

	t.customHeaderOrder = make([]string, len(order))
	for i, h := range order {
		t.customHeaderOrder[i] = strings.ToLower(h)
	}
}

func (t *Transport) GetHeaderOrder() []string {
	t.customHeaderOrderMu.RLock()
	defer t.customHeaderOrderMu.RUnlock()

	if len(t.customHeaderOrder) > 0 {
		result := make([]string, len(t.customHeaderOrder))
		copy(result, t.customHeaderOrder)
		return result
	}

	if len(t.preset.HeaderOrder) > 0 {
		result := make([]string, len(t.preset.HeaderOrder))
		for i, hp := range t.preset.HeaderOrder {
			result[i] = hp.Key
		}
		return result
	}

	return nil
}

func (t *Transport) getHeaderOrder() []string {
	t.customHeaderOrderMu.RLock()
	defer t.customHeaderOrderMu.RUnlock()
	return t.customHeaderOrder
}

func (t *Transport) getCustomPseudoOrder() []string {
	return t.customPseudoOrder
}

func (c *TransportConfig) GetConnectHost(requestHost string) string {
	if c == nil || c.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := c.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

func (c *TransportConfig) GetECHConfig(ctx context.Context, targetHost string) []byte {
	if c == nil {
		echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
		return echConfig
	}

	if len(c.ECHConfig) > 0 {
		return c.ECHConfig
	}

	if c.ECHConfigDomain != "" {
		echConfig, _ := dns.FetchECHConfigs(ctx, c.ECHConfigDomain)
		return echConfig
	}

	echConfig, _ := dns.FetchECHConfigs(ctx, targetHost)
	return echConfig
}

func (t *Transport) Do(ctx context.Context, req *Request) (*Response, error) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "", err)
	}

	if parsedURL.Scheme == "http" {
		return t.doHTTP1(ctx, req)
	}

	if t.proxy != nil && (t.proxy.URL != "" || t.proxy.TCPProxy != "" || t.proxy.UDPProxy != "") {
		effectiveProxyURL := t.proxy.URL
		if effectiveProxyURL == "" {
			effectiveProxyURL = t.proxy.TCPProxy
		}
		if effectiveProxyURL == "" {
			effectiveProxyURL = t.proxy.UDPProxy
		}

		switch t.protocol {
		case ProtocolHTTP1:
			return t.doHTTP1(ctx, req)

		case ProtocolHTTP2:
			return t.doHTTP2(ctx, req)

		case ProtocolHTTP3:
			if t.h3ProxyError != nil {
				return nil, t.h3ProxyError
			}
			if !SupportsQUIC(effectiveProxyURL) {
				return nil, fmt.Errorf("HTTP/3 requires a SOCKS5 or MASQUE proxy (current proxy does not support UDP)")
			}
			return t.doHTTP3(ctx, req)

		case ProtocolAuto:
			if t.h3ProxyError != nil {
				resp, err := t.doHTTP2(ctx, req)
				if err == nil {
					return resp, nil
				}
				var alpnErr *ALPNMismatchError
				if errors.As(err, &alpnErr) {
					return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
				}
				return t.doHTTP1(ctx, req)
			}

			if SupportsQUIC(effectiveProxyURL) {
				resp, err := t.doHTTP3(ctx, req)
				if err == nil {
					return resp, nil
				}
				resp, err = t.doHTTP2(ctx, req)
				if err == nil {
					return resp, nil
				}
				var alpnErr *ALPNMismatchError
				if errors.As(err, &alpnErr) {
					return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
				}
				return t.doHTTP1(ctx, req)
			}
			resp, err := t.doHTTP2(ctx, req)
			if err == nil {
				return resp, nil
			}
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			}
			return t.doHTTP1(ctx, req)

		default:
			return t.doHTTP2(ctx, req)
		}
	}

	switch t.protocol {
	case ProtocolHTTP1:
		return t.doHTTP1(ctx, req)
	case ProtocolHTTP2:
		return t.doHTTP2(ctx, req)
	case ProtocolHTTP3:
		return t.doHTTP3(ctx, req)
	case ProtocolAuto:
		return t.doAuto(ctx, req)
	default:
		return t.doHTTP2(ctx, req)
	}
}

func (t *Transport) doAuto(ctx context.Context, req *Request) (*Response, error) {
	host := extractHost(req.URL)

	t.protocolSupportMu.RLock()
	knownProtocol, known := t.protocolSupport[host]
	t.protocolSupportMu.RUnlock()

	if known {
		switch knownProtocol {
		case ProtocolHTTP3:
			return t.doHTTP3(ctx, req)
		case ProtocolHTTP2:
			resp, err := t.doHTTP2(ctx, req)
			if err == nil {
				return resp, nil
			}
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				return t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			}
			return t.doHTTP1(ctx, req)
		case ProtocolHTTP1:
			return t.doHTTP1(ctx, req)
		}
	}

	if t.preset.SupportHTTP3 {
		resp, protocol, err := t.raceH3H2(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = protocol
			t.protocolSupportMu.Unlock()
			return resp, nil
		}
		var alpnErr *ALPNMismatchError
		if errors.As(err, &alpnErr) {
			resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			if err == nil {
				t.protocolSupportMu.Lock()
				t.protocolSupport[host] = ProtocolHTTP1
				t.protocolSupportMu.Unlock()
			}
			return resp, err
		}
	} else {
		resp, err := t.doHTTP2(ctx, req)
		if err == nil {
			t.protocolSupportMu.Lock()
			t.protocolSupport[host] = ProtocolHTTP2
			t.protocolSupportMu.Unlock()
			return resp, nil
		}
		var alpnErr *ALPNMismatchError
		if errors.As(err, &alpnErr) {
			resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			if err == nil {
				t.protocolSupportMu.Lock()
				t.protocolSupport[host] = ProtocolHTTP1
				t.protocolSupportMu.Unlock()
			}
			return resp, err
		}
	}

	resp, err := t.doHTTP1(ctx, req)
	if err == nil {
		t.protocolSupportMu.Lock()
		t.protocolSupport[host] = ProtocolHTTP1
		t.protocolSupportMu.Unlock()
		return resp, nil
	}

	return nil, err
}

type connectResult struct {
	protocol Protocol
	err      error
}

func (t *Transport) raceH3H2(ctx context.Context, req *Request) (*Response, Protocol, error) {
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, ProtocolHTTP2, err
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	winnerCh := make(chan Protocol, 1)
	alpnErrCh := make(chan *ALPNMismatchError, 1)
	doneCh := make(chan struct{})

	go func() {
		err := t.h3Transport.Connect(raceCtx, host, port)
		if err == nil {
			select {
			case winnerCh <- ProtocolHTTP3:
			default:
			}
		}
	}()

	go func() {
		err := t.h2Transport.Connect(raceCtx, host, port)
		if err == nil {
			select {
			case winnerCh <- ProtocolHTTP2:
			default:
			}
		} else {
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				select {
				case alpnErrCh <- alpnErr:
				default:
				}
			}
		}
	}()

	go func() {
		select {
		case <-time.After(6 * time.Second):
		case <-raceCtx.Done():
		}
		close(doneCh)
	}()

	var winningProtocol Protocol
	select {
	case winningProtocol = <-winnerCh:
		cancel() // Cancel the other connection attempt
		select {
		case alpnErr := <-alpnErrCh:
			alpnErr.TLSConn.Close()
		default:
		}
	case alpnErr := <-alpnErrCh:
		cancel()
		resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
		return resp, ProtocolHTTP1, err
	case <-doneCh:
		cancel()
		select {
		case alpnErr := <-alpnErrCh:
			resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
			return resp, ProtocolHTTP1, err
		default:
		}
		resp, err := t.doHTTP2(ctx, req)
		if err != nil {
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
				return resp, ProtocolHTTP1, err
			}
			resp, err = t.doHTTP1(ctx, req)
			return resp, ProtocolHTTP1, err
		}
		return resp, ProtocolHTTP2, nil
	case <-ctx.Done():
		select {
		case alpnErr := <-alpnErrCh:
			alpnErr.TLSConn.Close()
		default:
		}
		return nil, ProtocolHTTP2, ctx.Err()
	}

	switch winningProtocol {
	case ProtocolHTTP3:
		resp, err := t.doHTTP3(ctx, req)
		return resp, ProtocolHTTP3, err
	case ProtocolHTTP2:
		resp, err := t.doHTTP2(ctx, req)
		if err != nil {
			var alpnErr *ALPNMismatchError
			if errors.As(err, &alpnErr) {
				resp, err := t.doHTTP1WithTLSConn(ctx, req, alpnErr)
				return resp, ProtocolHTTP1, err
			}
			resp, err = t.doHTTP1(ctx, req)
			return resp, ProtocolHTTP1, err
		}
		return resp, ProtocolHTTP2, nil
	default:
		resp, err := t.doHTTP2(ctx, req)
		return resp, ProtocolHTTP2, err
	}
}

func isProtocolError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "protocol") ||
		strings.Contains(errStr, "alpn") ||
		strings.Contains(errStr, "http2") ||
		strings.Contains(errStr, "does not support")
}

func (t *Transport) doHTTP1(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		if parsedURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), t.getCustomPseudoOrder(), effectiveTLSOnly, "h1", req.Headers)

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	reqStart := time.Now()

	resp, err := t.h1Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h1", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h1", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody() // Release pooled buffer on error
			return nil, NewRequestError("decompress", host, port, "h1", err)
		}
		releaseBody() // Release original pooled buffer after decompression
		body = decompressed
		releaseBody = func() {} // Decompressed buffer is not pooled
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h1",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

func (t *Transport) doHTTP1WithTLSConn(ctx context.Context, req *Request, alpnErr *ALPNMismatchError) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		alpnErr.TLSConn.Close()
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}

	host := alpnErr.Host
	port := alpnErr.Port

	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		alpnErr.TLSConn.Close()
		return nil, NewRequestError("create_request", host, port, "h1", err)
	}

	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), t.getCustomPseudoOrder(), effectiveTLSOnly, "h1", req.Headers)

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	reqStart := time.Now()

	resp, err := t.h1Transport.RoundTripWithTLSConn(httpReq, alpnErr.TLSConn, host, port)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h1", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h1", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody()
			return nil, NewRequestError("decompress", host, port, "h1", err)
		}
		releaseBody()
		body = decompressed
		releaseBody = func() {}
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   parsedURL.String(),
		Timing:     timing,
		Protocol:   "h1",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

func (t *Transport) doHTTP2(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h2", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, NewProtocolError("", "", "h2",
			&TransportError{Op: "scheme_check", Cause: ErrProtocol, Category: ErrProtocol})
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	useCountBefore := t.h2Transport.GetConnectionUseCount(host, port)

	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h2", err)
	}

	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), t.getCustomPseudoOrder(), effectiveTLSOnly, "h2", req.Headers)

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	reqStart := time.Now()

	resp, err := t.h2Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h2", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h2", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody()
			return nil, NewRequestError("decompress", host, port, "h2", err)
		}
		releaseBody()
		body = decompressed
		releaseBody = func() {}
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	wasReused := useCountBefore >= 1
	if wasReused {
		timing.DNSLookup = 0
		timing.TCPConnect = 0
		timing.TLSHandshake = 0
	} else {
		connectionOverhead := timing.FirstByte * 0.7
		if connectionOverhead > 10 {
			timing.DNSLookup = connectionOverhead * 0.2
			timing.TCPConnect = connectionOverhead * 0.3
			timing.TLSHandshake = connectionOverhead * 0.5
		}
	}

	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h2",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

func (t *Transport) doHTTP3(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h3", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, NewProtocolError("", "", "h3",
			&TransportError{Op: "scheme_check", Cause: ErrProtocol, Category: ErrProtocol})
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	dialCountBefore := t.h3Transport.GetDialCount()

	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, "h3", err)
	}

	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}

	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), t.getCustomPseudoOrder(), effectiveTLSOnly, "h3", req.Headers)

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	reqStart := time.Now()

	resp, err := t.h3Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, "h3", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	body, releaseBody, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, "h3", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	if contentEncoding != "" {
		decompressed, err := decompress(body, contentEncoding)
		if err != nil {
			releaseBody()
			return nil, NewRequestError("decompress", host, port, "h3", err)
		}
		releaseBody()
		body = decompressed
		releaseBody = func() {}
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	dialCountAfter := t.h3Transport.GetDialCount()
	wasReused := dialCountAfter == dialCountBefore
	timing.TCPConnect = 0

	if wasReused {
		timing.DNSLookup = 0
		timing.TLSHandshake = 0
	} else {
		connectionOverhead := timing.FirstByte * 0.7
		if connectionOverhead > 10 {
			timing.DNSLookup = connectionOverhead * 0.3
			timing.TLSHandshake = connectionOverhead * 0.7
		}
	}

	headers := buildHeadersMap(resp.Header)

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   req.URL,
		Timing:     timing,
		Protocol:   "h3",
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

func (t *Transport) Close() {
	t.h1Transport.Close()
	t.h2Transport.Close()
	t.h3Transport.Close()
}

func (t *Transport) Refresh() {
	t.h1Transport.Refresh()
	t.h2Transport.Refresh()
	t.h3Transport.Refresh()
}

func (t *Transport) RefreshWithProtocol(p Protocol) {
	t.h1Transport.Refresh()
	t.h2Transport.Refresh()
	t.h3Transport.Refresh()
	t.SetProtocol(p)
	t.ClearProtocolCache()
}

func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"http1": t.h1Transport.Stats(),
		"http2": t.h2Transport.Stats(),
		"http3": t.h3Transport.Stats(),
	}
}

func (t *Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

func (t *Transport) ClearProtocolCache() {
	t.protocolSupportMu.Lock()
	t.protocolSupport = make(map[string]Protocol)
	t.protocolSupportMu.Unlock()
}

func (t *Transport) GetHTTP1Transport() *HTTP1Transport {
	return t.h1Transport
}

func (t *Transport) GetHTTP2Transport() *HTTP2Transport {
	return t.h2Transport
}

func (t *Transport) GetHTTP3Transport() *HTTP3Transport {
	return t.h3Transport
}

func (t *Transport) GetConfig() *TransportConfig {
	return t.config
}

func (t *Transport) SetSessionIdentifier(sessionId string) {
	if t.h1Transport != nil {
		if cache := t.h1Transport.GetSessionCache(); cache != nil {
			if pCache, ok := cache.(*PersistableSessionCache); ok {
				pCache.SetSessionIdentifier(sessionId)
			}
		}
	}
	if t.h2Transport != nil {
		if cache := t.h2Transport.GetSessionCache(); cache != nil {
			if pCache, ok := cache.(*PersistableSessionCache); ok {
				pCache.SetSessionIdentifier(sessionId)
			}
		}
	}
	if t.h3Transport != nil {
		if cache := t.h3Transport.GetSessionCache(); cache != nil {
			if pCache, ok := cache.(*PersistableSessionCache); ok {
				pCache.SetSessionIdentifier(sessionId)
			}
		}
	}
}

func applyPresetHeaders(httpReq *http.Request, preset *fingerprint.Preset, customHeaderOrder []string, customPseudoOrder []string, tlsOnly bool, protocol string, userHeaders map[string][]string) {
	if !tlsOnly {
		if len(preset.HeaderOrder) > 0 {
			for _, hp := range preset.HeaderOrder {
				httpReq.Header.Set(hp.Key, hp.Value)
			}
		} else {
			for key, value := range preset.Headers {
				httpReq.Header.Set(key, value)
			}
		}
		httpReq.Header.Set("User-Agent", preset.UserAgent)

		if sniffXHRMode(httpReq.Method, userHeaders) {
			userMode := headerVal(userHeaders, "Sec-Fetch-Mode")
			userDest := headerVal(userHeaders, "Sec-Fetch-Dest")
			userSite := headerVal(userHeaders, "Sec-Fetch-Site")
			if userMode != "" {
				httpReq.Header.Set("Sec-Fetch-Mode", userMode)
			} else {
				httpReq.Header.Set("Sec-Fetch-Mode", "cors")
			}
			if userDest != "" {
				httpReq.Header.Set("Sec-Fetch-Dest", userDest)
			} else {
				httpReq.Header.Set("Sec-Fetch-Dest", "empty")
			}
			if userSite != "" {
				httpReq.Header.Set("Sec-Fetch-Site", userSite)
			} else {
				httpReq.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			httpReq.Header.Del("Sec-Fetch-User")
			httpReq.Header.Del("sec-fetch-user")
			httpReq.Header.Del("Upgrade-Insecure-Requests")
			httpReq.Header.Del("upgrade-insecure-requests")
			if headerVal(userHeaders, "Accept") == "" {
				httpReq.Header.Set("Accept", "*/*")
			}
			if httpReq.Header.Get("Priority") != "" {
				httpReq.Header.Set("Priority", "u=1, i")
			}
			if httpReq.Header.Get("priority") != "" {
				httpReq.Header.Set("priority", "u=1, i")
			}
		}

		if (protocol == "h2" || protocol == "h3") && preset.H2HasPriorityTable() {
			dest := httpReq.Header.Get("Sec-Fetch-Dest")
			if _, _, hv, ok := preset.H2PriorityFor(dest); ok {
				if hv == "" {
					httpReq.Header.Del("Priority")
					httpReq.Header.Del("priority")
				} else {
					httpReq.Header.Set("Priority", hv)
					if _, hasLower := httpReq.Header["priority"]; hasLower {
						httpReq.Header["priority"] = []string{hv}
					}
				}
			}
		}

		if protocol == "h1" && isChromePreset(preset.Name) {
			httpReq.Header.Del("Priority")
			httpReq.Header.Del("priority")
		}
	} else {
		httpReq.Header.Set("User-Agent", "")
	}

	if len(customHeaderOrder) > 0 {
		httpReq.Header[http.HeaderOrderKey] = customHeaderOrder
	} else {
		httpReq.Header[http.HeaderOrderKey] = preset.H2HeaderOrder()
	}

	if len(customPseudoOrder) > 0 {
		httpReq.Header[http.PHeaderOrderKey] = customPseudoOrder
	} else if order := preset.H2PseudoHeaderOrder(); order != nil {
		httpReq.Header[http.PHeaderOrderKey] = order
	} else if preset.HTTP2Settings.NoRFC7540Priorities {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":scheme", ":path", ":authority"}
	} else {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	}
}

func sniffXHRMode(method string, userHeaders map[string][]string) bool {
	method = strings.ToUpper(method)

	if v := headerVal(userHeaders, "Sec-Fetch-Mode"); v != "" {
		switch strings.ToLower(v) {
		case "cors", "no-cors", "websocket":
			return true
		case "navigate":
			return false
		}
	}
	if v := headerVal(userHeaders, "Sec-Fetch-Dest"); v != "" {
		if strings.ToLower(v) == "document" {
			return false
		}
		return true
	}

	if v := headerVal(userHeaders, "Accept"); v != "" && isAPIAcceptValue(v) {
		return true
	}

	switch method {
	case "GET", "HEAD", "OPTIONS", "":
		return false
	case "DELETE":
		return true
	}

	if ct := headerVal(userHeaders, "Content-Type"); ct != "" {
		if isFormContentTypeValue(ct) {
			return false
		}
		if isAPIContentTypeValue(ct) {
			return true
		}
	}

	return true
}

func headerVal(h map[string][]string, name string) string {
	if h == nil {
		return ""
	}
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func isAPIAcceptValue(accept string) bool {
	lower := strings.ToLower(accept)
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/xml") ||
		strings.Contains(lower, "text/plain") ||
		strings.Contains(lower, "application/octet-stream") ||
		lower == "*/*"
}

func isFormContentTypeValue(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(lower, "multipart/form-data")
}

func isAPIContentTypeValue(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/json") ||
		strings.HasPrefix(lower, "application/xml") ||
		strings.HasPrefix(lower, "application/octet-stream") ||
		strings.HasPrefix(lower, "application/grpc") ||
		strings.HasPrefix(lower, "application/x-protobuf") ||
		strings.HasPrefix(lower, "text/plain") ||
		(strings.HasPrefix(lower, "application/") && !isFormContentTypeValue(lower))
}

func isChromePreset(name string) bool {
	return strings.HasPrefix(name, "chrome-") || strings.HasPrefix(name, "Chrome")
}

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func buildHeadersMap(h http.Header) map[string][]string {
	headers := make(map[string][]string)
	for key, values := range h {
		lowerKey := strings.ToLower(key)
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}
	return headers
}

func readBodyOptimized(body io.Reader, contentLength int64) ([]byte, func(), error) {
	if contentLength > 0 {
		if contentLength <= 100*1024*1024 {
			bufPtr, release := getPooledBuffer(contentLength)
			buf := (*bufPtr)[:contentLength]
			n, err := io.ReadFull(body, buf)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				release()
				return nil, nil, err
			}
			return buf[:n], release, nil
		}
		buf := make([]byte, contentLength)
		n, err := io.ReadFull(body, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, nil, err
		}
		return buf[:n], func() {}, nil
	}
	bufPtr, release := getPooledBuffer(1 * 1024 * 1024)
	buf := *bufPtr
	n := 0
	for {
		if n == len(buf) {
			release() // release pool buffer, we're outgrowing it
			release = func() {}
			newBuf := make([]byte, len(buf)*2)
			copy(newBuf, buf[:n])
			buf = newBuf
		}
		nn, err := body.Read(buf[n:])
		n += nn
		if err == io.EOF {
			break
		}
		if err != nil {
			release()
			return nil, nil, err
		}
	}
	result := make([]byte, n)
	copy(result, buf[:n])
	release()
	return result, func() {}, nil
}

func decompress(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)

	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "zstd":
		decoder, err := zstd.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		return io.ReadAll(decoder)

	case "deflate":
		reader := flate.NewReader(bytes.NewReader(data))
		defer reader.Close()
		return io.ReadAll(reader)

	case "", "identity":
		return data, nil

	default:
		return data, nil
	}
}
