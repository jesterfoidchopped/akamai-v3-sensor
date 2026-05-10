package client

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	http "github.com/sardanioss/http"
	"io"
	"math"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/pool"
	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
	"github.com/klauspost/compress/zstd"
)

type Client struct {
	poolManager       *pool.Manager
	quicManager       *pool.QUICManager
	masqueTransport   *transport.HTTP3Transport // MASQUE proxy transport (if using MASQUE)
	socks5H3Transport *transport.HTTP3Transport // SOCKS5 UDP relay transport for HTTP/3
	h1Transport       *transport.HTTP1Transport
	preset            *fingerprint.Preset
	config            *ClientConfig

	auth Auth

	cookies *CookieJar

	hooks *Hooks

	certPinner *CertPinner

	h3Failures   map[string]time.Time
	h3FailuresMu sync.RWMutex

	h2Failures   map[string]time.Time
	h2FailuresMu sync.RWMutex

	h3InitError error

	customHeaderOrder   []string
	customHeaderOrderMu sync.RWMutex
}

func NewClient(presetName string, opts ...Option) *Client {
	config := DefaultConfig()
	config.Preset = presetName
	for _, opt := range opts {
		opt(config)
	}

	preset := fingerprint.Get(config.Preset)

	tcpProxyURL := config.TCPProxy
	if tcpProxyURL == "" {
		tcpProxyURL = config.Proxy
	}
	udpProxyURL := config.UDPProxy
	if udpProxyURL == "" {
		udpProxyURL = config.Proxy
	}

	var h2Manager *pool.Manager
	if tcpProxyURL != "" {
		h2Manager = pool.NewManagerWithProxy(preset, tcpProxyURL, config.InsecureSkipVerify)
	} else {
		h2Manager = pool.NewManagerWithTLSConfig(preset, config.InsecureSkipVerify)
	}

	if config.PreferIPv4 {
		h2Manager.GetDNSCache().SetPreferIPv4(true)
	}

	var transportConfig *transport.TransportConfig
	if config.TLSOnly || len(config.ConnectTo) > 0 || config.ECHConfigDomain != "" || len(config.ECHConfig) > 0 {
		transportConfig = &transport.TransportConfig{
			TLSOnly:         config.TLSOnly,
			ConnectTo:       config.ConnectTo,
			ECHConfigDomain: config.ECHConfigDomain,
			ECHConfig:       config.ECHConfig,
		}
	}

	var quicManager *pool.QUICManager
	var masqueTransport *transport.HTTP3Transport
	var socks5H3Transport *transport.HTTP3Transport
	var h3InitError error
	if !config.DisableH3 {
		if udpProxyURL != "" && transport.IsMASQUEProxy(udpProxyURL) {
			proxyConfig := &transport.ProxyConfig{URL: udpProxyURL}
			var err error
			masqueTransport, err = transport.NewHTTP3TransportWithMASQUE(preset, h2Manager.GetDNSCache(), proxyConfig, transportConfig)
			if err != nil {
				masqueTransport = nil
				h3InitError = err
			}
		} else if udpProxyURL != "" && transport.IsSOCKS5Proxy(udpProxyURL) {
			proxyConfig := &transport.ProxyConfig{URL: udpProxyURL}
			var err error
			socks5H3Transport, err = transport.NewHTTP3TransportWithConfig(preset, h2Manager.GetDNSCache(), proxyConfig, transportConfig)
			if err != nil {
				socks5H3Transport = nil
				h3InitError = err
			}
		} else if udpProxyURL == "" {
			quicManager = pool.NewQUICManager(preset, h2Manager.GetDNSCache())
		}
	}

	var tcpProxyConfig *transport.ProxyConfig
	if tcpProxyURL != "" {
		tcpProxyConfig = &transport.ProxyConfig{URL: tcpProxyURL}
	}
	h1Transport := transport.NewHTTP1TransportWithConfig(preset, h2Manager.GetDNSCache(), tcpProxyConfig, transportConfig)
	h1Transport.SetInsecureSkipVerify(config.InsecureSkipVerify)

	if quicManager != nil {
		quicManager.SetInsecureSkipVerify(config.InsecureSkipVerify)
	}
	if masqueTransport != nil {
		masqueTransport.SetInsecureSkipVerify(config.InsecureSkipVerify)
	}
	if socks5H3Transport != nil {
		socks5H3Transport.SetInsecureSkipVerify(config.InsecureSkipVerify)
	}

	for requestHost, connectHost := range config.ConnectTo {
		h2Manager.SetConnectTo(requestHost, connectHost)
		if quicManager != nil {
			quicManager.SetConnectTo(requestHost, connectHost)
		}
		h1Transport.SetConnectTo(requestHost, connectHost)
	}

	if len(config.ECHConfig) > 0 {
		h2Manager.SetECHConfig(config.ECHConfig)
		if quicManager != nil {
			quicManager.SetECHConfig(config.ECHConfig)
		}
	}
	if config.ECHConfigDomain != "" {
		h2Manager.SetECHConfigDomain(config.ECHConfigDomain)
		if quicManager != nil {
			quicManager.SetECHConfigDomain(config.ECHConfigDomain)
		}
	}
	if config.DisableECH {
		if quicManager != nil {
			quicManager.SetDisableECH(true)
		}
	}

	client := &Client{
		poolManager:       h2Manager,
		quicManager:       quicManager,
		masqueTransport:   masqueTransport,
		socks5H3Transport: socks5H3Transport,
		h1Transport:       h1Transport,
		preset:            preset,
		config:            config,
		h3Failures:        make(map[string]time.Time),
		h2Failures:        make(map[string]time.Time),
		h3InitError:       h3InitError,
	}

	if config.RetryEnabled {
		client.cookies = NewCookieJar()
	}

	return client
}

func NewSession(presetName string, opts ...Option) *Client {
	defaultOpts := []Option{WithRetry(3)}
	opts = append(defaultOpts, opts...)

	client := NewClient(presetName, opts...)
	client.cookies = NewCookieJar()
	return client
}

func (c *Client) SetPreset(presetName string) {
	c.preset = fingerprint.Get(presetName)
	c.poolManager.SetPreset(c.preset)
}

func (c *Client) SetTimeout(timeout time.Duration) {
	c.config.Timeout = timeout
}

func (c *Client) SetForceProtocol(p Protocol) {
	c.config.ForceProtocol = p
}

func (c *Client) SetAuth(auth Auth) {
	c.auth = auth
}

func (c *Client) SetBasicAuth(username, password string) {
	c.auth = NewBasicAuth(username, password)
}

func (c *Client) SetBearerAuth(token string) {
	c.auth = NewBearerAuth(token)
}

func (c *Client) EnableCookies() {
	if c.cookies == nil {
		c.cookies = NewCookieJar()
	}
}

func (c *Client) DisableCookies() {
	c.cookies = nil
}

func (c *Client) Cookies() *CookieJar {
	return c.cookies
}

func (c *Client) ClearCookies() {
	if c.cookies != nil {
		c.cookies.Clear()
	}
}

func (c *Client) Hooks() *Hooks {
	if c.hooks == nil {
		c.hooks = NewHooks()
	}
	return c.hooks
}

func (c *Client) OnPreRequest(hook PreRequestHook) *Client {
	c.Hooks().OnPreRequest(hook)
	return c
}

func (c *Client) OnPostResponse(hook PostResponseHook) *Client {
	c.Hooks().OnPostResponse(hook)
	return c
}

func (c *Client) ClearHooks() {
	if c.hooks != nil {
		c.hooks.Clear()
	}
}

func (c *Client) CertPinner() *CertPinner {
	if c.certPinner == nil {
		c.certPinner = NewCertPinner()
	}
	return c.certPinner
}

func (c *Client) PinCertificate(hash string, opts ...PinOption) *Client {
	c.CertPinner().AddPin(hash, opts...)
	return c
}

func (c *Client) PinCertificateFromFile(certPath string, opts ...PinOption) error {
	return c.CertPinner().AddPinFromCertFile(certPath, opts...)
}

func (c *Client) ClearPins() {
	if c.certPinner != nil {
		c.certPinner.Clear()
	}
}

type FetchMode int

const (
	FetchModeNavigate FetchMode = iota // Default: human clicked link (sec-fetch-mode: navigate)
	FetchModeCORS                      // XHR/fetch call (sec-fetch-mode: cors)
	FetchModeNoCors                    // Subresource load (script/style/image): sec-fetch-mode: no-cors
)

type FetchSite int

const (
	FetchSiteAuto       FetchSite = iota // Auto-detect based on Referer header
	FetchSiteNone                        // Direct navigation (typed URL, bookmark)
	FetchSiteSameOrigin                  // Same origin request
	FetchSiteSameSite                    // Same site but different subdomain
	FetchSiteCrossSite                   // Different site
)

type Request struct {
	Method  string
	URL     string
	Headers map[string][]string // Multi-value headers (matches http.Header)
	Body    io.Reader           // Streaming body for uploads
	Timeout time.Duration

	UserAgent     string    // Override User-Agent (empty = use preset)
	ForceProtocol Protocol  // Force specific protocol (ProtocolAuto = auto)
	FetchMode     FetchMode // Fetch mode: Navigate (default, human click) or CORS (XHR/fetch) or NoCors (subresource)
	FetchSite     FetchSite // Sec-Fetch-Site: Auto (default), None, SameOrigin, SameSite, CrossSite
	FetchDest     string    // Sec-Fetch-Dest for NoCors mode: "script", "style", "image" (empty = use mode default)
	Referer       string    // Referer header (used for auto-detecting FetchSite)

	Auth Auth

	Params map[string]string

	FollowRedirects *bool
	MaxRedirects    int

	DisableRetry bool
}

func (r *Request) SetHeader(key, value string) {
	if r.Headers == nil {
		r.Headers = make(map[string][]string)
	}
	r.Headers[key] = []string{value}
}

func (r *Request) AddHeader(key, value string) {
	if r.Headers == nil {
		r.Headers = make(map[string][]string)
	}
	r.Headers[key] = append(r.Headers[key], value)
}

func (r *Request) GetHeader(key string) string {
	if values, ok := getHeaderCaseInsensitive(r.Headers, key); ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func getHeaderCaseInsensitive(headers map[string][]string, key string) ([]string, bool) {
	if headers == nil {
		return nil, false
	}
	if values, ok := headers[key]; ok {
		return values, true
	}
	keyLower := strings.ToLower(key)
	for k, v := range headers {
		if strings.ToLower(k) == keyLower {
			return v, true
		}
	}
	return nil, false
}

type Response struct {
	StatusCode int
	Headers    map[string][]string // Multi-value headers (matches http.Header)
	Body       io.ReadCloser       // Streaming body - call Close() when done
	FinalURL   string
	Timing     *protocol.Timing
	Protocol   string // "h3" or "h2"

	Request *Request

	RedirectHistory []*RedirectInfo

	bodyBytes []byte
	bodyRead  bool
}

func (r *Response) Close() error {
	if r.Body != nil {
		return r.Body.Close()
	}
	return nil
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

type RedirectInfo struct {
	StatusCode int
	URL        string
	Headers    map[string][]string // Multi-value headers
}

func (r *Response) JSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (r *Response) Text() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}
	return string(data), nil
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

func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

func (r *Response) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

func (r *Response) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

func (r *Response) IsServerError() bool {
	return r.StatusCode >= 500 && r.StatusCode < 600
}

func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	if c.config.RetryEnabled && !req.DisableRetry {
		return c.doWithRetry(ctx, req)
	}
	return c.doOnce(ctx, req, nil)
}

func (c *Client) doWithRetry(ctx context.Context, req *Request) (*Response, error) {
	var lastErr error
	var lastResp *Response
	var cookieChallengeRetried bool

	var cachedBody []byte
	if req.Body != nil {
		var err error
		cachedBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			wait := c.calculateRetryWait(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		reqCopy := *req
		if cachedBody != nil {
			reqCopy.Body = bytes.NewReader(cachedBody)
		}

		if cookieChallengeRetried && req.ForceProtocol == ProtocolAuto && (c.quicManager != nil || c.masqueTransport != nil) {
			reqCopy.ForceProtocol = ProtocolHTTP3
		}

		resp, err := c.doOnce(ctx, &reqCopy, nil)
		if err != nil {
			lastErr = err
			continue
		}

		isChallengeStatus := resp.StatusCode == 403 || resp.StatusCode == 429
		if isChallengeStatus && !cookieChallengeRetried && req.ForceProtocol == ProtocolAuto {
			if setCookies := resp.Headers["set-cookie"]; len(setCookies) > 0 {
				cookieChallengeRetried = true
				continue
			}
		}

		if c.shouldRetryStatus(resp.StatusCode) && attempt < c.config.MaxRetries {
			lastResp = resp
			lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}

	if lastResp != nil {
		return lastResp, nil
	}
	return nil, fmt.Errorf("request failed after %d retries: %w", c.config.MaxRetries, lastErr)
}

func (c *Client) calculateRetryWait(attempt int) time.Duration {
	wait := float64(c.config.RetryWaitMin) * math.Pow(2, float64(attempt-1))

	jitter := wait * 0.2 * (rand.Float64()*2 - 1)
	wait += jitter

	if wait > float64(c.config.RetryWaitMax) {
		wait = float64(c.config.RetryWaitMax)
	}

	return time.Duration(wait)
}

func (c *Client) shouldRetryStatus(statusCode int) bool {
	for _, code := range c.config.RetryOnStatus {
		if statusCode == code {
			return true
		}
	}
	return false
}

func (c *Client) doOnce(ctx context.Context, req *Request, redirectHistory []*RedirectInfo) (*Response, error) {
	startTime := time.Now()

	reqURL := req.URL
	if len(req.Params) > 0 {
		reqURL = NewURLBuilder(req.URL).Params(req.Params).Build()
	}

	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS is supported")
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	timeout := c.config.Timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostKey := host + ":" + port
	useH3 := c.shouldTryHTTP3(hostKey)

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	normalizeRequestWithBody(httpReq, bodyBytes)

	if c.config.TLSOnly {
		applyTLSOnlyHeaders(httpReq, c.preset, req, parsedURL, c.getHeaderOrder())
	} else {
		applyModeHeaders(httpReq, c.preset, req, parsedURL, c.getHeaderOrder())
	}

	auth := req.Auth
	if auth == nil {
		auth = c.auth
	}
	if auth != nil {
		if err := auth.Apply(httpReq); err != nil {
			return nil, fmt.Errorf("failed to apply authentication: %w", err)
		}
	}

	if c.cookies != nil {
		cookieHeader := c.cookies.CookieHeader(parsedURL)
		if cookieHeader != "" {
			httpReq.Header.Set("Cookie", cookieHeader)
		}
	}

	applyOrganicJitter(httpReq)

	if c.hooks != nil {
		if err := c.hooks.RunPreRequest(httpReq); err != nil {
			return nil, fmt.Errorf("pre-request hook failed: %w", err)
		}
	}

	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}
	for key, values := range httpReq.Header {
		if key == http.HeaderOrderKey || key == http.PHeaderOrderKey {
			continue
		}
		if _, exists := getHeaderCaseInsensitive(req.Headers, key); !exists {
			req.Headers[key] = values
		}
	}

	var resp *http.Response
	var usedProtocol string
	timing := &protocol.Timing{}

	effectiveProtocol := req.ForceProtocol
	if effectiveProtocol == ProtocolAuto && c.config.ForceProtocol != ProtocolAuto {
		effectiveProtocol = c.config.ForceProtocol
	}

	switch effectiveProtocol {
	case ProtocolHTTP1:
		resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			return nil, err
		}
	case ProtocolHTTP3:
		if c.config.Proxy != "" && !transport.SupportsQUIC(c.config.Proxy) {
			return nil, fmt.Errorf("HTTP/3 requires SOCKS5 or MASQUE proxy: HTTP proxies cannot tunnel UDP")
		}
		if c.quicManager == nil && c.masqueTransport == nil && c.socks5H3Transport == nil {
			if c.h3InitError != nil {
				return nil, fmt.Errorf("HTTP/3 is disabled: %w", c.h3InitError)
			}
			return nil, fmt.Errorf("HTTP/3 is disabled (no QUIC transport available)")
		}
		resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			return nil, fmt.Errorf("HTTP/3 failed: %w", err)
		}
	case ProtocolHTTP2:
		resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			return nil, err
		}
	default:
		useH1 := c.shouldUseH1(hostKey)

		usesQUICProxy := c.config.Proxy != "" && transport.SupportsQUIC(c.config.Proxy)

		if useH1 && !usesQUICProxy {
			resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				return nil, err
			}
		} else if usesQUICProxy && useH3 {
			resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				c.markH3Failed(hostKey)
				resetRequestBody(httpReq, bodyBytes)
				resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
				if err != nil {
					resetRequestBody(httpReq, bodyBytes)
					resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
					if err != nil {
						return nil, err
					}
				}
			}
		} else {
			resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				if useH3 {
					resetRequestBody(httpReq, bodyBytes)
					resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
					if err != nil {
						c.markH3Failed(hostKey)
						resetRequestBody(httpReq, bodyBytes)
						resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
						if err != nil {
							return nil, err
						}
					}
				} else {
					c.markH2Failed(hostKey)
					resetRequestBody(httpReq, bodyBytes)
					resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	if c.certPinner != nil && c.certPinner.HasPins() && resp.TLS != nil {
		if err := c.certPinner.Verify(host, resp.TLS.PeerCertificates); err != nil {
			resp.Body.Close()
			return nil, err
		}
	}

	defer resp.Body.Close()

	headers := make(map[string][]string)
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}

	setCookies := resp.Header["Set-Cookie"]
	if c.cookies != nil && len(setCookies) > 0 {
		c.cookies.SetCookiesFromHeaderList(parsedURL, setCookies)
	}

	if isRedirect(resp.StatusCode) {
		followRedirects := c.config.FollowRedirects
		if req.FollowRedirects != nil {
			followRedirects = *req.FollowRedirects
		}

		if followRedirects {
			maxRedirects := c.config.MaxRedirects
			if req.MaxRedirects > 0 {
				maxRedirects = req.MaxRedirects
			}

			if redirectHistory == nil {
				redirectHistory = make([]*RedirectInfo, 0)
			}

			if len(redirectHistory) >= maxRedirects {
				return nil, fmt.Errorf("too many redirects (max %d)", maxRedirects)
			}

			location := resp.Header.Get("Location")
			if location == "" {
				return nil, fmt.Errorf("redirect response missing Location header")
			}

			redirectURL := JoinURL(reqURL, location)

			redirectHistory = append(redirectHistory, &RedirectInfo{
				StatusCode: resp.StatusCode,
				URL:        reqURL,
				Headers:    headers,
			})

			newMethod := method
			if resp.StatusCode == 303 || (resp.StatusCode == 301 || resp.StatusCode == 302) && method == "POST" {
				newMethod = "GET"
			}

			schemeDowngrade := isSchemeDowngradeClient(reqURL, redirectURL)
			crossOrigin := !sameOriginClient(reqURL, redirectURL)

			var carriedHeaders map[string][]string
			if len(req.Headers) > 0 {
				carriedHeaders = make(map[string][]string, len(req.Headers))
				for k, v := range req.Headers {
					lk := strings.ToLower(k)
					if schemeDowngrade && lk == "referer" {
						continue
					}
					if (crossOrigin || schemeDowngrade) && (lk == "authorization" || lk == "proxy-authorization") {
						continue
					}
					carriedHeaders[k] = v
				}
			}

			carriedReferer := reqURL
			carriedAuth := req.Auth
			if schemeDowngrade {
				carriedReferer = ""
				carriedAuth = nil
			} else if crossOrigin {
				carriedAuth = nil
			}

			newReq := &Request{
				Method:          newMethod,
				URL:             redirectURL,
				Headers:         carriedHeaders,
				Timeout:         req.Timeout,
				UserAgent:       req.UserAgent,
				ForceProtocol:   req.ForceProtocol,
				FetchMode:       req.FetchMode,
				FetchSite:       FetchSiteCrossSite, // Redirects are usually cross-site
				Referer:         carriedReferer,
				Auth:            carriedAuth,
				FollowRedirects: req.FollowRedirects,
				MaxRedirects:    req.MaxRedirects,
				DisableRetry:    true, // Don't retry redirects
			}

			if resp.StatusCode == 307 || resp.StatusCode == 308 {
				if len(bodyBytes) > 0 {
					newReq.Body = bytes.NewReader(bodyBytes)
				}
			}

			return c.doOnce(ctx, newReq, redirectHistory)
		}
	}

	if resp.StatusCode == http.StatusUnauthorized && auth != nil {
		shouldRetry, err := auth.HandleChallenge(resp, httpReq)
		if err != nil {
			return nil, fmt.Errorf("failed to handle auth challenge: %w", err)
		}
		if shouldRetry {
			resetRequestBody(httpReq, bodyBytes)
			if len(bodyBytes) > 0 {
				req.Body = bytes.NewReader(bodyBytes)
			}
			if err := auth.Apply(httpReq); err != nil {
				return nil, fmt.Errorf("failed to apply authentication after challenge: %w", err)
			}
			return c.doOnce(ctx, req, redirectHistory)
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	respBody, err = decompress(respBody, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	response := &Response{
		StatusCode:      resp.StatusCode,
		Headers:         headers,
		Body:            io.NopCloser(bytes.NewReader(respBody)),
		FinalURL:        reqURL,
		Timing:          timing,
		Protocol:        usedProtocol,
		Request:         req,
		RedirectHistory: redirectHistory,
		bodyBytes:       respBody,
		bodyRead:        true,
	}

	if c.hooks != nil {
		if err := c.hooks.RunPostResponse(response); err != nil {
		}
	}

	return response, nil
}

func isRedirect(statusCode int) bool {
	return statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308
}

func (c *Client) shouldTryHTTP3(hostKey string) bool {
	if c.quicManager == nil && c.masqueTransport == nil && c.socks5H3Transport == nil {
		return false
	}

	c.h3FailuresMu.RLock()
	defer c.h3FailuresMu.RUnlock()

	if failTime, exists := c.h3Failures[hostKey]; exists {
		if time.Since(failTime) < 5*time.Minute {
			return false
		}
	}
	return true
}

func (c *Client) markH3Failed(hostKey string) {
	c.h3FailuresMu.Lock()
	defer c.h3FailuresMu.Unlock()
	c.h3Failures[hostKey] = time.Now()
}

func (c *Client) doHTTP3(ctx context.Context, host, port string, httpReq *http.Request, timing *protocol.Timing, startTime time.Time) (*http.Response, string, error) {
	connStart := time.Now()

	if c.masqueTransport != nil {
		firstByteTime := time.Now()
		resp, err := c.masqueTransport.RoundTrip(httpReq)
		if err != nil {
			return nil, "", err
		}
		timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
		return resp, "h3", nil
	}

	if c.socks5H3Transport != nil {
		firstByteTime := time.Now()
		resp, err := c.socks5H3Transport.RoundTrip(httpReq)
		if err != nil {
			return nil, "", err
		}
		timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
		return resp, "h3", nil
	}

	conn, err := c.quicManager.GetConn(ctx, host, port)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get QUIC connection: %w", err)
	}

	if conn.UseCount == 1 {
		connTime := float64(time.Since(connStart).Milliseconds())
		timing.DNSLookup = connTime / 3
		timing.TCPConnect = 0
		timing.TLSHandshake = connTime * 2 / 3
	}

	firstByteTime := time.Now()
	resp, err := conn.HTTP3RT.RoundTrip(httpReq)
	if err != nil {
		return nil, "", err
	}

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
	return resp, "h3", nil
}

func (c *Client) doHTTP2(ctx context.Context, host, port string, httpReq *http.Request, timing *protocol.Timing, startTime time.Time) (*http.Response, string, error) {
	connStart := time.Now()

	conn, err := c.poolManager.GetConn(ctx, host, port)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get connection: %w", err)
	}

	if conn.UseCount == 1 {
		connTime := float64(time.Since(connStart).Milliseconds())
		timing.DNSLookup = connTime / 3
		timing.TCPConnect = connTime / 3
		timing.TLSHandshake = connTime / 3
	}

	firstByteTime := time.Now()
	resp, err := conn.HTTP2Conn.RoundTrip(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
	return resp, "h2", nil
}

func (c *Client) doHTTP1(ctx context.Context, host, port string, httpReq *http.Request, timing *protocol.Timing, startTime time.Time) (*http.Response, string, error) {
	firstByteTime := time.Now()

	resp, err := c.h1Transport.RoundTrip(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP/1.1 request failed: %w", err)
	}

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())
	return resp, "h1", nil
}

func (c *Client) markH2Failed(hostKey string) {
	c.h2FailuresMu.Lock()
	c.h2Failures[hostKey] = time.Now()
	c.h2FailuresMu.Unlock()
}

func (c *Client) shouldUseH1(hostKey string) bool {
	c.h2FailuresMu.RLock()
	failTime, failed := c.h2Failures[hostKey]
	c.h2FailuresMu.RUnlock()

	if !failed {
		return false
	}

	if time.Since(failTime) > 5*time.Minute {
		c.h2FailuresMu.Lock()
		delete(c.h2Failures, hostKey)
		c.h2FailuresMu.Unlock()
		return false
	}

	return true
}

func (c *Client) Get(ctx context.Context, url string, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

func (c *Client) Post(ctx context.Context, url string, body io.Reader, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

func (c *Client) Close() {
	c.poolManager.Close()
	if c.quicManager != nil {
		c.quicManager.Close()
	}
	if c.masqueTransport != nil {
		c.masqueTransport.Close()
	}
	if c.socks5H3Transport != nil {
		c.socks5H3Transport.Close()
	}
	if c.h1Transport != nil {
		c.h1Transport.Close()
	}
}

func (c *Client) CloseQUICConnections() {
	if c.quicManager != nil {
		c.quicManager.CloseAllConnections()
	}
}

func (c *Client) SetProxy(proxyURL string) {
	c.SetTCPProxy(proxyURL)
	c.SetUDPProxy(proxyURL)
}

func (c *Client) SetTCPProxy(proxyURL string) {
	c.poolManager.SetProxy(proxyURL)

	var proxyConfig *transport.ProxyConfig
	if proxyURL != "" {
		proxyConfig = &transport.ProxyConfig{URL: proxyURL}
	}
	c.h1Transport.SetProxy(proxyConfig)

	c.config.TCPProxy = proxyURL
	if c.config.Proxy == c.config.UDPProxy || c.config.UDPProxy == "" {
		c.config.Proxy = proxyURL
	}

	c.h2FailuresMu.Lock()
	c.h2Failures = make(map[string]time.Time)
	c.h2FailuresMu.Unlock()
}

func (c *Client) SetUDPProxy(proxyURL string) {
	if c.quicManager != nil {
		c.quicManager.Close()
		c.quicManager = nil
	}
	if c.masqueTransport != nil {
		c.masqueTransport.Close()
		c.masqueTransport = nil
	}
	if c.socks5H3Transport != nil {
		c.socks5H3Transport.Close()
		c.socks5H3Transport = nil
	}

	c.config.UDPProxy = proxyURL
	if c.config.Proxy == c.config.TCPProxy || c.config.TCPProxy == "" {
		c.config.Proxy = proxyURL
	}

	if proxyURL != "" && transport.IsMASQUEProxy(proxyURL) {
		proxyConfig := &transport.ProxyConfig{URL: proxyURL}
		masqueTransport, err := transport.NewHTTP3TransportWithMASQUE(c.preset, c.poolManager.GetDNSCache(), proxyConfig, nil)
		if err == nil {
			c.masqueTransport = masqueTransport
			if c.config.InsecureSkipVerify {
				c.masqueTransport.SetInsecureSkipVerify(true)
			}
		}
	} else if proxyURL != "" && transport.IsSOCKS5Proxy(proxyURL) {
		proxyConfig := &transport.ProxyConfig{URL: proxyURL}
		socks5Transport, err := transport.NewHTTP3TransportWithProxy(c.preset, c.poolManager.GetDNSCache(), proxyConfig)
		if err == nil {
			c.socks5H3Transport = socks5Transport
			if c.config.InsecureSkipVerify {
				c.socks5H3Transport.SetInsecureSkipVerify(true)
			}
		}
	} else if proxyURL == "" {
		c.quicManager = pool.NewQUICManager(c.preset, c.poolManager.GetDNSCache())
		if c.config.InsecureSkipVerify {
			c.quicManager.SetInsecureSkipVerify(true)
		}
	}

	c.h3FailuresMu.Lock()
	c.h3Failures = make(map[string]time.Time)
	c.h3FailuresMu.Unlock()
}

func (c *Client) GetProxy() string {
	return c.poolManager.GetProxy()
}

func (c *Client) GetTCPProxy() string {
	return c.poolManager.GetProxy()
}

func (c *Client) GetUDPProxy() string {
	return c.config.UDPProxy
}

func (c *Client) SetHeaderOrder(order []string) {
	c.customHeaderOrderMu.Lock()
	defer c.customHeaderOrderMu.Unlock()

	if len(order) == 0 {
		c.customHeaderOrder = nil
		return
	}

	c.customHeaderOrder = make([]string, len(order))
	for i, h := range order {
		c.customHeaderOrder[i] = strings.ToLower(h)
	}
}

func (c *Client) GetHeaderOrder() []string {
	c.customHeaderOrderMu.RLock()
	defer c.customHeaderOrderMu.RUnlock()

	if len(c.customHeaderOrder) > 0 {
		result := make([]string, len(c.customHeaderOrder))
		copy(result, c.customHeaderOrder)
		return result
	}

	if len(c.preset.HeaderOrder) > 0 {
		result := make([]string, len(c.preset.HeaderOrder))
		for i, hp := range c.preset.HeaderOrder {
			result[i] = hp.Key
		}
		return result
	}

	return nil
}

func (c *Client) getHeaderOrder() []string {
	c.customHeaderOrderMu.RLock()
	defer c.customHeaderOrderMu.RUnlock()
	return c.customHeaderOrder
}

func (c *Client) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	return c.poolManager.Stats()
}

func applyTLSOnlyHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request, parsedURL *url.URL, customHeaderOrder []string) {
	httpReq.Header.Set("Host", parsedURL.Hostname())

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	if _, hasUA := getHeaderCaseInsensitive(req.Headers, "User-Agent"); !hasUA {
		httpReq.Header.Set("User-Agent", "") // Empty string prevents Go from adding default
	}

	if len(customHeaderOrder) > 0 {
		httpReq.Header[http.HeaderOrderKey] = customHeaderOrder
	} else {
		httpReq.Header[http.HeaderOrderKey] = preset.H2HeaderOrder()
	}

	if order := preset.H2PseudoHeaderOrder(); order != nil {
		httpReq.Header[http.PHeaderOrderKey] = order
	} else if preset.HTTP2Settings.NoRFC7540Priorities {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":scheme", ":path", ":authority"}
	} else {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	}
}

func applyModeHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request, parsedURL *url.URL, customHeaderOrder []string) {
	userAgent := preset.UserAgent
	if req.UserAgent != "" {
		userAgent = req.UserAgent
	}
	httpReq.Header.Set("User-Agent", userAgent)

	httpReq.Header.Set("Host", parsedURL.Hostname())

	if req.Referer != "" {
		httpReq.Header.Set("Referer", req.Referer)
	}

	effectiveMode := req.FetchMode
	if effectiveMode == FetchModeNavigate {
		if sniffXHRMode(req) {
			effectiveMode = FetchModeCORS
		}
	}

	secFetchSite := detectSecFetchSiteForMode(req.FetchSite, parsedURL, req.Referer, effectiveMode)
	httpReq.Header.Set("Sec-Fetch-Site", secFetchSite)

	switch effectiveMode {
	case FetchModeCORS:
		applyCORSModeHeaders(httpReq, preset, req, parsedURL)
	case FetchModeNoCors:
		applyNoCorsHeaders(httpReq, preset, req)
	default:
		applyNavigationModeHeaders(httpReq, preset, req)
	}

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	if len(customHeaderOrder) > 0 {
		httpReq.Header[http.HeaderOrderKey] = customHeaderOrder
	} else {
		httpReq.Header[http.HeaderOrderKey] = preset.H2HeaderOrder()
	}

	if order := preset.H2PseudoHeaderOrder(); order != nil {
		httpReq.Header[http.PHeaderOrderKey] = order
	} else if preset.HTTP2Settings.NoRFC7540Priorities {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":scheme", ":path", ":authority"}
	} else {
		httpReq.Header[http.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}
	}
}

func isAPIAcceptHeader(accept string) bool {
	lower := strings.ToLower(accept)
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/xml") ||
		strings.Contains(lower, "text/plain") ||
		strings.Contains(lower, "application/octet-stream") ||
		(lower == "*/*")
}

func isFormContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/x-www-form-urlencoded") ||
		strings.HasPrefix(lower, "multipart/form-data")
}

func isAPIContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.HasPrefix(lower, "application/json") ||
		strings.HasPrefix(lower, "application/xml") ||
		strings.HasPrefix(lower, "application/octet-stream") ||
		strings.HasPrefix(lower, "application/grpc") ||
		strings.HasPrefix(lower, "application/x-protobuf") ||
		strings.HasPrefix(lower, "text/plain") ||
		(strings.HasPrefix(lower, "application/") && !isFormContentType(lower))
}

func sniffXHRMode(req *Request) bool {
	method := strings.ToUpper(req.Method)

	if v, ok := getHeaderCaseInsensitive(req.Headers, "Sec-Fetch-Mode"); ok && len(v) > 0 {
		switch strings.ToLower(v[0]) {
		case "cors", "no-cors", "websocket":
			return true
		case "navigate":
			return false
		}
	}
	if v, ok := getHeaderCaseInsensitive(req.Headers, "Sec-Fetch-Dest"); ok && len(v) > 0 {
		if strings.ToLower(v[0]) == "document" {
			return false
		}
		return true
	}

	if accept, ok := getHeaderCaseInsensitive(req.Headers, "Accept"); ok && len(accept) > 0 {
		if isAPIAcceptHeader(accept[0]) {
			return true
		}
	}

	switch method {
	case "GET", "HEAD", "OPTIONS", "":
		return false
	case "DELETE":
		return true
	}

	if ct, ok := getHeaderCaseInsensitive(req.Headers, "Content-Type"); ok && len(ct) > 0 {
		if isFormContentType(ct[0]) {
			return false
		}
		if isAPIContentType(ct[0]) {
			return true
		}
	}

	return true
}

func applyNavigationModeHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request) {
	if v, ok := preset.Headers["sec-ch-ua"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-mobile"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Mobile", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-platform"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Platform", v)
	}

	if v, ok := preset.Headers["Accept"]; ok {
		httpReq.Header.Set("Accept", v)
	} else {
		httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	}
	if v, ok := preset.Headers["Accept-Encoding"]; ok {
		httpReq.Header.Set("Accept-Encoding", v)
	} else {
		httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	}
	if v, ok := preset.Headers["Accept-Language"]; ok {
		httpReq.Header.Set("Accept-Language", v)
	} else {
		httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	httpReq.Header.Set("Sec-Fetch-Dest", "document")
	httpReq.Header.Set("Sec-Fetch-Mode", "navigate")
	httpReq.Header.Set("Sec-Fetch-User", "?1")
	httpReq.Header.Set("Upgrade-Insecure-Requests", "1")

	if v, ok := preset.Headers["Priority"]; ok {
		httpReq.Header.Set("Priority", v)
	}

	if v, ok := preset.Headers["TE"]; ok {
		httpReq.Header.Set("TE", v)
	}
}

func applyCORSModeHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request, parsedURL *url.URL) {
	if v, ok := preset.Headers["sec-ch-ua"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-mobile"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Mobile", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-platform"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Platform", v)
	}

	if acceptValues, ok := getHeaderCaseInsensitive(req.Headers, "Accept"); ok && len(acceptValues) > 0 && acceptValues[0] != "" {
		httpReq.Header.Set("Accept", acceptValues[0])
	} else {
		httpReq.Header.Set("Accept", "*/*")
	}
	if v, ok := preset.Headers["Accept-Encoding"]; ok {
		httpReq.Header.Set("Accept-Encoding", v)
	} else {
		httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	}
	if v, ok := preset.Headers["Accept-Language"]; ok {
		httpReq.Header.Set("Accept-Language", v)
	} else {
		httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	httpReq.Header.Set("Sec-Fetch-Dest", "empty")
	httpReq.Header.Set("Sec-Fetch-Mode", "cors")

	if req.Referer != "" {
		if refURL, err := url.Parse(req.Referer); err == nil {
			httpReq.Header.Set("Origin", refURL.Scheme+"://"+refURL.Host)
		}
	} else {
		httpReq.Header.Set("Origin", parsedURL.Scheme+"://"+parsedURL.Host)
	}

	httpReq.Header.Set("Priority", "u=1, i")
}

func applyNoCorsHeaders(httpReq *http.Request, preset *fingerprint.Preset, req *Request) {
	if v, ok := preset.Headers["sec-ch-ua"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-mobile"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Mobile", v)
	}
	if v, ok := preset.Headers["sec-ch-ua-platform"]; ok {
		httpReq.Header.Set("Sec-Ch-Ua-Platform", v)
	}

	dest := req.FetchDest
	switch dest {
	case "style":
		httpReq.Header.Set("Accept", "text/css,*/*;q=0.1")
	case "image":
		httpReq.Header.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
	default: // "script", "empty", etc.
		httpReq.Header.Set("Accept", "*/*")
	}

	httpReq.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.9")

	httpReq.Header.Set("Sec-Fetch-Mode", "no-cors")
	if dest != "" {
		httpReq.Header.Set("Sec-Fetch-Dest", dest)
	} else {
		httpReq.Header.Set("Sec-Fetch-Dest", "empty")
	}
}

func detectSecFetchSiteForMode(fetchSite FetchSite, requestURL *url.URL, referer string, mode FetchMode) string {
	switch fetchSite {
	case FetchSiteNone:
		if mode == FetchModeCORS {
		} else {
			return "none"
		}
	case FetchSiteSameOrigin:
		return "same-origin"
	case FetchSiteSameSite:
		return "same-site"
	case FetchSiteCrossSite:
		return "cross-site"
	}

	if referer == "" {
		if mode == FetchModeCORS || mode == FetchModeNoCors {
			return "cross-site"
		}
		return "none"
	}

	refererURL, err := url.Parse(referer)
	if err != nil {
		if mode == FetchModeCORS || mode == FetchModeNoCors {
			return "cross-site"
		}
		return "none"
	}

	if requestURL.Scheme == refererURL.Scheme &&
		requestURL.Host == refererURL.Host {
		return "same-origin"
	}

	requestSite := extractSite(requestURL.Hostname())
	refererSite := extractSite(refererURL.Hostname())

	if requestSite == refererSite && requestURL.Scheme == refererURL.Scheme {
		return "same-site"
	}

	return "cross-site"
}

func extractSite(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}

	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}

	if len(parts) >= 3 && len(parts[len(parts)-2]) <= 3 {
		return strings.Join(parts[len(parts)-3:], ".")
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

func applyOrganicJitter(req *http.Request) {
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

func parseOriginClient(urlStr string) (scheme, host, port string) {
	u, err := url.Parse(urlStr)
	if err != nil || u.Scheme == "" {
		return "", "", ""
	}
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Hostname())
	port = u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, host, port
}

func sameOriginClient(a, b string) bool {
	as, ah, ap := parseOriginClient(a)
	bs, bh, bp := parseOriginClient(b)
	if as == "" || bs == "" {
		return false
	}
	return as == bs && ah == bh && ap == bp
}

func isSchemeDowngradeClient(from, to string) bool {
	fs, _, _ := parseOriginClient(from)
	ts, _, _ := parseOriginClient(to)
	return fs == "https" && ts == "http"
}
