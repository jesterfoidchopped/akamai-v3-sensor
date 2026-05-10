package sensor

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/textproto"
	"strings"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/client"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/jesterfoidchopped/akamai-v3-sensor/session"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
	tls "github.com/sardanioss/utls"
)

var systemRoots *x509.CertPool

func init() {
	systemRoots, _ = x509.SystemCertPool()
}

type Client struct {
	inner   *client.Client
	timeout time.Duration
}

type Option func(*clientConfig)

type clientConfig struct {
	timeout time.Duration
	proxy   string
}

func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = d
	}
}

func WithProxy(proxyURL string) Option {
	return func(c *clientConfig) {
		c.proxy = proxyURL
	}
}

func New(preset string, opts ...Option) *Client {
	cfg := &clientConfig{
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	var clientOpts []client.Option
	if cfg.proxy != "" {
		clientOpts = append(clientOpts, client.WithProxy(cfg.proxy))
	}

	return &Client{
		inner:   client.NewClient(preset, clientOpts...),
		timeout: cfg.timeout,
	}
}

type MultipartField struct {
	Name        string // Form field name
	Value       string // Text value (used when Filename is empty)
	Filename    string // If set, this field is a file upload
	Content     []byte // File content (used when Filename is set)
	ContentType string // MIME type for file uploads (default: application/octet-stream)
}

func BuildMultipart(fields []MultipartField) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, f := range fields {
		if f.Filename != "" {
			ct := f.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			part, err := w.CreatePart(textproto.MIMEHeader{
				"Content-Disposition": {fmt.Sprintf(`form-data; name="%s"; filename="%s"`, f.Name, f.Filename)},
				"Content-Type":        {ct},
			})
			if err != nil {
				return nil, "", err
			}
			if _, err := part.Write(f.Content); err != nil {
				return nil, "", err
			}
		} else {
			if err := w.WriteField(f.Name, f.Value); err != nil {
				return nil, "", err
			}
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

type Request struct {
	Method  string
	URL     string
	Headers map[string][]string // Multi-value headers (matches http.Header)
	Body    io.Reader           // Streaming body for uploads
	Timeout time.Duration

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
	Protocol   string
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

func (r *Response) JSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
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

func (c *Client) Do(ctx context.Context, req *Request) (*Response, error) {
	timeout := req.Timeout
	if timeout == 0 {
		timeout = c.timeout
	}

	cReq := &client.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
		Timeout: timeout,
	}

	resp, err := c.inner.Do(ctx, cReq)
	if err != nil {
		return nil, err
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
	}, nil
}

func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method: "GET",
		URL:    url,
	})
}

func (c *Client) GetWithHeaders(ctx context.Context, url string, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

func (c *Client) Post(ctx context.Context, url string, body io.Reader, contentType string) (*Response, error) {
	headers := map[string][]string{}
	if contentType != "" {
		headers["Content-Type"] = []string{contentType}
	}
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Headers: headers,
		Body:    body,
	})
}

func (c *Client) PostJSON(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, bytes.NewReader(body), "application/json")
}

func (c *Client) PostForm(ctx context.Context, url string, body []byte) (*Response, error) {
	return c.Post(ctx, url, bytes.NewReader(body), "application/x-www-form-urlencoded")
}

func (c *Client) PostMultipart(ctx context.Context, url string, fields []MultipartField) (*Response, error) {
	body, contentType, err := BuildMultipart(fields)
	if err != nil {
		return nil, err
	}
	return c.Post(ctx, url, bytes.NewReader(body), contentType)
}

func (c *Client) Close() {
	c.inner.Close()
}

type Session struct {
	inner     *session.Session
	configErr error // deferred config error (e.g. invalid Akamai string)
}

type SessionOption func(*sessionConfig)

type sessionConfig struct {
	preset               string
	proxy                string
	tcpProxy             string // Proxy for TCP-based protocols (HTTP/1.1, HTTP/2)
	udpProxy             string // Proxy for UDP-based protocols (HTTP/3 via MASQUE)
	timeout              time.Duration
	forceHTTP1           bool
	forceHTTP2           bool
	forceHTTP3           bool
	disableHTTP3         bool
	insecureSkipVerify   bool
	disableRedirects     bool
	maxRedirects         int
	retryCount           int
	retryWaitMin         time.Duration
	retryWaitMax         time.Duration
	retryOnStatus        []int
	preferIPv4           bool
	connectTo            map[string]string // Domain fronting: request_host -> connect_host
	echConfigDomain      string            // Domain to fetch ECH config from
	tlsOnly              bool              // TLS-only mode: skip preset headers, set all manually
	quicIdleTimeout      time.Duration     // QUIC idle timeout (default: 30s)
	localAddr            string            // Local IP address to bind outgoing connections
	keyLogFile           string            // Path to write TLS key log for Wireshark decryption
	disableECH           bool              // Disable ECH lookup for faster first request
	enableSpeculativeTLS bool              // Enable speculative TLS optimization for proxy connections
	switchProtocol       string            // Protocol to switch to after Refresh() (e.g. "h1", "h2", "h3")
	withoutCookieJar     bool              // Disable internal cookie jar entirely (caller manages cookies via headers)

	sessionCacheBackend       transport.SessionCacheBackend
	sessionCacheErrorCallback transport.ErrorCallback

	customJA3            string
	customJA3Extras      *fingerprint.JA3Extras
	customH2Settings     *fingerprint.HTTP2Settings
	customPseudoOrder    []string
	customTCPFingerprint *fingerprint.TCPFingerprint

	configErr error // deferred error from option parsing
}

func WithSessionProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.proxy = proxyURL
	}
}

func WithSessionTCPProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.tcpProxy = proxyURL
	}
}

func WithSessionUDPProxy(proxyURL string) SessionOption {
	return func(c *sessionConfig) {
		c.udpProxy = proxyURL
	}
}

func WithSessionTimeout(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.timeout = d
	}
}

func WithForceHTTP1() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP1 = true
	}
}

func WithForceHTTP2() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP2 = true
	}
}

func WithForceHTTP3() SessionOption {
	return func(c *sessionConfig) {
		c.forceHTTP3 = true
	}
}

func WithDisableHTTP3() SessionOption {
	return func(c *sessionConfig) {
		c.disableHTTP3 = true
	}
}

func WithInsecureSkipVerify() SessionOption {
	return func(c *sessionConfig) {
		c.insecureSkipVerify = true
	}
}

func WithoutRedirects() SessionOption {
	return func(c *sessionConfig) {
		c.disableRedirects = true
	}
}

func WithRedirects(follow bool, maxRedirects int) SessionOption {
	return func(c *sessionConfig) {
		c.disableRedirects = !follow
		c.maxRedirects = maxRedirects
	}
}

func WithRetry(count int) SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = count
	}
}

func WithoutRetry() SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = 0
	}
}

func WithRetryConfig(count int, waitMin, waitMax time.Duration, retryOnStatus []int) SessionOption {
	return func(c *sessionConfig) {
		c.retryCount = count
		c.retryWaitMin = waitMin
		c.retryWaitMax = waitMax
		c.retryOnStatus = retryOnStatus
	}
}

func WithSessionPreferIPv4() SessionOption {
	return func(c *sessionConfig) {
		c.preferIPv4 = true
	}
}

func WithLocalAddress(addr string) SessionOption {
	return func(c *sessionConfig) {
		c.localAddr = addr
	}
}

func WithLocalAddrIP(ip net.IP) SessionOption {
	return func(c *sessionConfig) {
		if ip == nil {
			return
		}
		c.localAddr = ip.String()
	}
}

func WithKeyLogFile(path string) SessionOption {
	return func(c *sessionConfig) {
		c.keyLogFile = path
	}
}

func WithDisableECH() SessionOption {
	return func(c *sessionConfig) {
		c.disableECH = true
	}
}

func WithEnableSpeculativeTLS() SessionOption {
	return func(c *sessionConfig) {
		c.enableSpeculativeTLS = true
	}
}

func WithSwitchProtocol(protocol string) SessionOption {
	return func(c *sessionConfig) {
		c.switchProtocol = protocol
	}
}

func WithoutCookieJar() SessionOption {
	return func(c *sessionConfig) {
		c.withoutCookieJar = true
	}
}

func WithConnectTo(requestHost, connectHost string) SessionOption {
	return func(c *sessionConfig) {
		if c.connectTo == nil {
			c.connectTo = make(map[string]string)
		}
		c.connectTo[requestHost] = connectHost
	}
}

func WithECHFrom(domain string) SessionOption {
	return func(c *sessionConfig) {
		c.echConfigDomain = domain
	}
}

func WithTLSOnly() SessionOption {
	return func(c *sessionConfig) {
		c.tlsOnly = true
	}
}

func WithQuicIdleTimeout(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.quicIdleTimeout = d
	}
}

func WithSessionCache(backend transport.SessionCacheBackend, errorCallback transport.ErrorCallback) SessionOption {
	return func(c *sessionConfig) {
		c.sessionCacheBackend = backend
		c.sessionCacheErrorCallback = errorCallback
	}
}

type CustomFingerprint struct {
	JA3 string

	Akamai string

	SignatureAlgorithms []string

	ALPN []string

	CertCompression []string

	PermuteExtensions bool
}

func WithTCPFingerprint(fp fingerprint.TCPFingerprint) SessionOption {
	return func(c *sessionConfig) {
		c.customTCPFingerprint = &fp
	}
}

func WithCustomFingerprint(fp CustomFingerprint) SessionOption {
	return func(c *sessionConfig) {
		c.customJA3 = fp.JA3

		if fp.JA3 != "" {
			extras := &fingerprint.JA3Extras{
				PermuteExtensions: fp.PermuteExtensions,
				RecordSizeLimit:   0x4001,
			}
			if len(fp.ALPN) > 0 {
				extras.ALPN = fp.ALPN
			}
			if len(fp.SignatureAlgorithms) > 0 {
				extras.SignatureAlgorithms = parseSignatureAlgorithms(fp.SignatureAlgorithms)
			}
			if len(fp.CertCompression) > 0 {
				extras.CertCompAlgs = parseCertCompression(fp.CertCompression)
			}
			c.customJA3Extras = extras
			c.tlsOnly = true
		}

		if fp.Akamai != "" {
			h2Settings, pseudoOrder, err := fingerprint.ParseAkamai(fp.Akamai)
			if err != nil {
				c.configErr = fmt.Errorf("invalid Akamai fingerprint: %w", err)
			} else {
				c.customH2Settings = h2Settings
				c.customPseudoOrder = pseudoOrder
			}
		}
	}
}

func NewSession(preset string, opts ...SessionOption) *Session {
	cfg := &sessionConfig{
		preset:  preset,
		timeout: 30 * time.Second,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	sessionCfg := &protocol.SessionConfig{
		Preset:               cfg.preset,
		Proxy:                cfg.proxy,
		TCPProxy:             cfg.tcpProxy,
		UDPProxy:             cfg.udpProxy,
		Timeout:              int(cfg.timeout.Seconds()),
		InsecureSkipVerify:   cfg.insecureSkipVerify,
		FollowRedirects:      !cfg.disableRedirects,
		MaxRedirects:         cfg.maxRedirects,
		PreferIPv4:           cfg.preferIPv4,
		ConnectTo:            cfg.connectTo,
		ECHConfigDomain:      cfg.echConfigDomain,
		TLSOnly:              cfg.tlsOnly,
		QuicIdleTimeout:      int(cfg.quicIdleTimeout.Seconds()),
		LocalAddress:         cfg.localAddr,
		KeyLogFile:           cfg.keyLogFile,
		DisableECH:           cfg.disableECH,
		EnableSpeculativeTLS: cfg.enableSpeculativeTLS,
		SwitchProtocol:       cfg.switchProtocol,
		WithoutCookieJar:     cfg.withoutCookieJar,
	}

	if cfg.retryCount > 0 {
		sessionCfg.RetryEnabled = true
		sessionCfg.MaxRetries = cfg.retryCount
		if cfg.retryWaitMin > 0 {
			sessionCfg.RetryWaitMin = int(cfg.retryWaitMin.Milliseconds())
		}
		if cfg.retryWaitMax > 0 {
			sessionCfg.RetryWaitMax = int(cfg.retryWaitMax.Milliseconds())
		}
		if len(cfg.retryOnStatus) > 0 {
			sessionCfg.RetryOnStatus = cfg.retryOnStatus
		}
	}

	if cfg.forceHTTP1 {
		sessionCfg.ForceHTTP1 = true
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP2 {
		sessionCfg.ForceHTTP2 = true
		sessionCfg.DisableHTTP3 = true
	}
	if cfg.forceHTTP3 {
		sessionCfg.ForceHTTP3 = true
	}
	if cfg.disableHTTP3 {
		sessionCfg.DisableHTTP3 = true
	}

	var s *session.Session
	needsOpts := cfg.sessionCacheBackend != nil || cfg.customJA3 != "" || cfg.customH2Settings != nil || len(cfg.customPseudoOrder) > 0 || cfg.customTCPFingerprint != nil
	if needsOpts {
		opts := &session.SessionOptions{
			SessionCacheBackend:       cfg.sessionCacheBackend,
			SessionCacheErrorCallback: cfg.sessionCacheErrorCallback,
			CustomJA3:                 cfg.customJA3,
			CustomJA3Extras:           cfg.customJA3Extras,
			CustomH2Settings:          cfg.customH2Settings,
			CustomPseudoOrder:         cfg.customPseudoOrder,
			CustomTCPFingerprint:      cfg.customTCPFingerprint,
		}
		s = session.NewSessionWithOptions("", sessionCfg, opts)
	} else {
		s = session.NewSession("", sessionCfg)
	}
	return &Session{inner: s, configErr: cfg.configErr}
}

func (s *Session) Do(ctx context.Context, req *Request) (*Response, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	sReq := &transport.Request{
		Method:     req.Method,
		URL:        req.URL,
		Headers:    req.Headers,
		BodyReader: req.Body,
		TLSOnly:    req.TLSOnly,
	}

	resp, err := s.inner.Request(ctx, sReq)
	if err != nil {
		return nil, err
	}

	var history []*RedirectInfo
	if len(resp.History) > 0 {
		history = make([]*RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = &RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		History:    history,
	}, nil
}

func (s *Session) DoWithBody(ctx context.Context, req *Request, bodyReader io.Reader) (*Response, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	sReq := &transport.Request{
		Method:     req.Method,
		URL:        req.URL,
		Headers:    req.Headers,
		BodyReader: bodyReader,
		TLSOnly:    req.TLSOnly,
	}

	resp, err := s.inner.Request(ctx, sReq)
	if err != nil {
		return nil, err
	}

	var history []*RedirectInfo
	if len(resp.History) > 0 {
		history = make([]*RedirectInfo, len(resp.History))
		for i, h := range resp.History {
			history[i] = &RedirectInfo{
				StatusCode: h.StatusCode,
				URL:        h.URL,
				Headers:    h.Headers,
			}
		}
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
		FinalURL:   resp.FinalURL,
		Protocol:   resp.Protocol,
		History:    history,
	}, nil
}

func (s *Session) Get(ctx context.Context, url string) (*Response, error) {
	return s.Do(ctx, &Request{Method: "GET", URL: url})
}

type CookieInfo = session.CookieState

func (s *Session) GetCookies() []CookieInfo {
	return s.inner.GetCookies()
}

func (s *Session) GetCookiesDetailed() []CookieInfo {
	return s.inner.GetCookies()
}

func (s *Session) SetCookie(cookie CookieInfo) {
	s.inner.SetCookie(cookie.Name, cookie.Value, cookie.Domain, cookie.Path, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.MaxAge, cookie.Expires)
}

func (s *Session) DeleteCookie(name, domain string) {
	s.inner.DeleteCookie(name, domain)
}

func (s *Session) ClearCookies() {
	s.inner.ClearCookies()
}

func (s *Session) SetProxy(proxyURL string) {
	s.inner.SetProxy(proxyURL)
}

func (s *Session) SetTCPProxy(proxyURL string) {
	s.inner.SetTCPProxy(proxyURL)
}

func (s *Session) SetUDPProxy(proxyURL string) {
	s.inner.SetUDPProxy(proxyURL)
}

func (s *Session) GetProxy() string {
	return s.inner.GetProxy()
}

func (s *Session) GetTCPProxy() string {
	return s.inner.GetTCPProxy()
}

func (s *Session) GetUDPProxy() string {
	return s.inner.GetUDPProxy()
}

func (s *Session) SetHeaderOrder(order []string) {
	s.inner.SetHeaderOrder(order)
}

func (s *Session) GetHeaderOrder() []string {
	return s.inner.GetHeaderOrder()
}

func (s *Session) SetSessionIdentifier(sessionId string) {
	s.inner.SetSessionIdentifier(sessionId)
}

func (s *Session) Stats() session.SessionStats {
	return s.inner.Stats()
}

func (s *Session) IdleTime() time.Duration {
	return s.inner.IdleTime()
}

func (s *Session) IsActive() bool {
	return s.inner.IsActive()
}

func (s *Session) Touch() {
	s.inner.Touch()
}

func (s *Session) ClearCache() {
	s.inner.ClearCache()
}

func (s *Session) GetTransport() *transport.Transport {
	return s.inner.GetTransport()
}

func (s *Session) Warmup(ctx context.Context, url string) error {
	return s.inner.Warmup(ctx, url)
}

func (s *Session) Fork(n int) []*Session {
	innerForks := s.inner.Fork(n)
	if innerForks == nil {
		return nil
	}
	forks := make([]*Session, len(innerForks))
	for i, inner := range innerForks {
		forks[i] = &Session{inner: inner}
	}
	return forks
}

func (s *Session) Close() {
	s.inner.Close()
}

func (s *Session) Refresh() {
	s.inner.Refresh()
}

func (s *Session) RefreshWithProtocol(protocol string) error {
	return s.inner.RefreshWithProtocol(protocol)
}

func (s *Session) Save(path string) error {
	return s.inner.Save(path)
}

func (s *Session) Marshal() ([]byte, error) {
	return s.inner.Marshal()
}

func LoadSession(path string) (*Session, error) {
	inner, err := session.LoadSession(path)
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner}, nil
}

func UnmarshalSession(data []byte) (*Session, error) {
	inner, err := session.UnmarshalSession(data)
	if err != nil {
		return nil, err
	}
	return &Session{inner: inner}, nil
}

type StreamResponse struct {
	StatusCode    int
	Headers       map[string][]string
	FinalURL      string
	Protocol      string
	ContentLength int64 // -1 if unknown (chunked encoding)

	inner *transport.StreamResponse
}

func (r *StreamResponse) Read(p []byte) (n int, err error) {
	return r.inner.Read(p)
}

func (r *StreamResponse) Close() error {
	return r.inner.Close()
}

func (r *StreamResponse) ReadAll() ([]byte, error) {
	return r.inner.ReadAll()
}

func (r *StreamResponse) ReadChunk(size int) ([]byte, error) {
	return r.inner.ReadChunk(size)
}

func (s *Session) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	sReq := &transport.Request{
		Method:     req.Method,
		URL:        req.URL,
		Headers:    req.Headers,
		BodyReader: req.Body,
		TLSOnly:    req.TLSOnly,
	}

	resp, err := s.inner.RequestStream(ctx, sReq)
	if err != nil {
		return nil, err
	}

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Headers,
		FinalURL:      resp.FinalURL,
		Protocol:      resp.Protocol,
		ContentLength: resp.ContentLength,
		inner:         resp,
	}, nil
}

func (s *Session) GetStream(ctx context.Context, url string) (*StreamResponse, error) {
	return s.DoStream(ctx, &Request{Method: "GET", URL: url})
}

func (s *Session) GetStreamWithHeaders(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error) {
	return s.DoStream(ctx, &Request{Method: "GET", URL: url, Headers: headers})
}

func Presets() []string {
	return fingerprint.Available()
}

func ValidateSessionFile(path string) error {
	return session.ValidateSessionFile(path)
}

func SetKeyLogWriter(w io.Writer) {
	transport.SetKeyLogWriter(w)
}

type Manager = session.Manager

func NewManager() *Manager {
	return session.NewManager()
}

func parseSignatureAlgorithms(names []string) []tls.SignatureScheme {
	m := map[string]tls.SignatureScheme{
		"ecdsa_secp256r1_sha256": tls.ECDSAWithP256AndSHA256,
		"ecdsa_secp384r1_sha384": tls.ECDSAWithP384AndSHA384,
		"ecdsa_secp521r1_sha512": tls.ECDSAWithP521AndSHA512,
		"rsa_pss_rsae_sha256":    tls.PSSWithSHA256,
		"rsa_pss_rsae_sha384":    tls.PSSWithSHA384,
		"rsa_pss_rsae_sha512":    tls.PSSWithSHA512,
		"rsa_pkcs1_sha256":       tls.PKCS1WithSHA256,
		"rsa_pkcs1_sha384":       tls.PKCS1WithSHA384,
		"rsa_pkcs1_sha512":       tls.PKCS1WithSHA512,
	}
	var result []tls.SignatureScheme
	for _, name := range names {
		if scheme, ok := m[strings.ToLower(name)]; ok {
			result = append(result, scheme)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseCertCompression(names []string) []tls.CertCompressionAlgo {
	m := map[string]tls.CertCompressionAlgo{
		"brotli": tls.CertCompressionBrotli,
		"zlib":   tls.CertCompressionZlib,
		"zstd":   tls.CertCompressionZstd,
	}
	var result []tls.CertCompressionAlgo
	for _, name := range names {
		if algo, ok := m[strings.ToLower(name)]; ok {
			result = append(result, algo)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
