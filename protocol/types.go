package protocol

type MessageType string

const (
	TypeRequest  MessageType = "request"
	TypeResponse MessageType = "response"

	TypeSessionCreate MessageType = "session.create"
	TypeSessionClose  MessageType = "session.close"
	TypeSessionList   MessageType = "session.list"

	TypeCookieGet   MessageType = "cookie.get"
	TypeCookieSet   MessageType = "cookie.set"
	TypeCookieClear MessageType = "cookie.clear"
	TypeCookieAll   MessageType = "cookie.all"

	TypePing     MessageType = "ping"
	TypePong     MessageType = "pong"
	TypeError    MessageType = "error"
	TypeShutdown MessageType = "shutdown"

	TypePresetList MessageType = "preset.list"
)

type Request struct {
	ID      string            `json:"id"`                // Unique request ID for correlation
	Type    MessageType       `json:"type"`              // Message type
	Session string            `json:"session,omitempty"` // Session ID (empty for one-shot requests)
	Method  string            `json:"method,omitempty"`  // HTTP method (GET, POST, etc.)
	URL     string            `json:"url,omitempty"`     // Target URL
	Headers map[string]string `json:"headers,omitempty"` // Custom headers
	Body    string            `json:"body,omitempty"`    // Request body (base64 encoded for binary)
	Options *RequestOptions   `json:"options,omitempty"` // Request options
}

type RequestOptions struct {
	Timeout int `json:"timeout,omitempty"`

	FollowRedirects *bool `json:"followRedirects,omitempty"` // nil = use session default
	MaxRedirects    int   `json:"maxRedirects,omitempty"`

	ForceProtocol string `json:"forceProtocol,omitempty"` // "auto", "h2", "h3"

	FetchMode string `json:"fetchMode,omitempty"` // "navigate" (default), "cors"
	FetchSite string `json:"fetchSite,omitempty"` // "auto", "none", "same-origin", "same-site", "cross-site"
	Referer   string `json:"referer,omitempty"`   // Referer header

	Auth *AuthConfig `json:"auth,omitempty"`

	Params map[string]string `json:"params,omitempty"`

	DisableRetry bool `json:"disableRetry,omitempty"`

	UserAgent string `json:"userAgent,omitempty"`

	BodyEncoding string `json:"bodyEncoding,omitempty"`
}

type AuthConfig struct {
	Type     string `json:"type"`               // "basic", "bearer", "digest"
	Username string `json:"username,omitempty"` // For basic/digest
	Password string `json:"password,omitempty"` // For basic/digest
	Token    string `json:"token,omitempty"`    // For bearer
}

type Response struct {
	ID       string            `json:"id"`                 // Correlates with request ID
	Type     MessageType       `json:"type"`               // Message type
	Session  string            `json:"session,omitempty"`  // Session ID if applicable
	Status   int               `json:"status,omitempty"`   // HTTP status code
	Headers  map[string]string `json:"headers,omitempty"`  // Response headers
	Body     string            `json:"body,omitempty"`     // Response body
	URL      string            `json:"url,omitempty"`      // Final URL after redirects
	Protocol string            `json:"protocol,omitempty"` // "h2" or "h3"
	Timing   *Timing           `json:"timing,omitempty"`   // Request timing breakdown
	Error    *ErrorInfo        `json:"error,omitempty"`    // Error details if failed

	BodyEncoding string `json:"bodyEncoding,omitempty"` // "text" or "base64"
	BodySize     int    `json:"bodySize,omitempty"`     // Original body size in bytes
}

type Timing struct {
	DNSLookup    float64 `json:"dnsLookup"`    // DNS lookup time (0 = cached/reused)
	TCPConnect   float64 `json:"tcpConnect"`   // TCP connection time (0 = reused)
	TLSHandshake float64 `json:"tlsHandshake"` // TLS handshake time (0 = reused)
	FirstByte    float64 `json:"firstByte"`    // Time to first response byte
	Total        float64 `json:"total"`        // Total request time
}

type ErrorInfo struct {
	Code    string `json:"code"`              // Error code (e.g., "TIMEOUT", "CONNECTION_REFUSED")
	Message string `json:"message"`           // Human-readable error message
	Details string `json:"details,omitempty"` // Additional details
}

type SessionCreateRequest struct {
	ID      string         `json:"id"`
	Type    MessageType    `json:"type"`
	Options *SessionConfig `json:"options,omitempty"`
}

type SessionConfig struct {
	Preset string `json:"preset,omitempty"`

	BaseURL string `json:"baseUrl,omitempty"`

	Proxy string `json:"proxy,omitempty"`

	TCPProxy string `json:"tcpProxy,omitempty"`

	UDPProxy string `json:"udpProxy,omitempty"`

	Timeout int `json:"timeout,omitempty"`

	FollowRedirects bool `json:"followRedirects,omitempty"`
	MaxRedirects    int  `json:"maxRedirects,omitempty"`

	RetryEnabled  bool  `json:"retryEnabled,omitempty"`
	MaxRetries    int   `json:"maxRetries,omitempty"`
	RetryWaitMin  int   `json:"retryWaitMin,omitempty"`  // Milliseconds
	RetryWaitMax  int   `json:"retryWaitMax,omitempty"`  // Milliseconds
	RetryOnStatus []int `json:"retryOnStatus,omitempty"` // Status codes to retry

	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`

	DisableKeepAlives bool `json:"disableKeepAlives,omitempty"`
	DisableHTTP3      bool `json:"disableHttp3,omitempty"`
	ForceHTTP1        bool `json:"forceHttp1,omitempty"`
	ForceHTTP2        bool `json:"forceHttp2,omitempty"`
	ForceHTTP3        bool `json:"forceHttp3,omitempty"`

	PreferIPv4   bool   `json:"preferIpv4,omitempty"`   // Prefer IPv4 addresses over IPv6
	LocalAddress string `json:"localAddress,omitempty"` // Local IP to bind outgoing connections (for IPv6 rotation)

	ConnectTo map[string]string `json:"connectTo,omitempty"`

	ECHConfigDomain string `json:"echConfigDomain,omitempty"`

	TLSOnly bool `json:"tlsOnly,omitempty"`

	QuicIdleTimeout int `json:"quicIdleTimeout,omitempty"`

	KeyLogFile string `json:"keyLogFile,omitempty"`

	DisableECH bool `json:"disableEch,omitempty"`

	EnableSpeculativeTLS bool `json:"enableSpeculativeTls,omitempty"`

	SwitchProtocol string `json:"switchProtocol,omitempty"`

	WithoutCookieJar bool `json:"withoutCookieJar,omitempty"`

	Auth *AuthConfig `json:"auth,omitempty"`
}

type SessionCreateResponse struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
	Error   *ErrorInfo  `json:"error,omitempty"`
}

type SessionCloseRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
}

type SessionListResponse struct {
	ID       string      `json:"id"`
	Type     MessageType `json:"type"`
	Sessions []string    `json:"sessions"`
}

type CookieGetRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
	URL     string      `json:"url"` // URL to get cookies for
}

type CookieSetRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
	URL     string      `json:"url"`               // URL domain for the cookie
	Name    string      `json:"name"`              // Cookie name
	Value   string      `json:"value"`             // Cookie value
	Path    string      `json:"path"`              // Cookie path (optional)
	Domain  string      `json:"domain"`            // Cookie domain (optional)
	Secure  bool        `json:"secure"`            // Secure flag
	Expires int64       `json:"expires,omitempty"` // Unix timestamp (0 = session cookie)
}

type CookieClearRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
}

type CookieAllRequest struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Session string      `json:"session"`
}

type Cookie struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Domain  string `json:"domain"`
	Path    string `json:"path"`
	Secure  bool   `json:"secure"`
	Expires int64  `json:"expires,omitempty"` // Unix timestamp
}

type CookieResponse struct {
	ID      string              `json:"id"`
	Type    MessageType         `json:"type"`
	Cookies map[string]string   `json:"cookies,omitempty"` // For simple get (name -> value)
	All     map[string][]Cookie `json:"all,omitempty"`     // For all cookies (domain -> cookies)
	Error   *ErrorInfo          `json:"error,omitempty"`
}

type PresetListResponse struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Presets []string    `json:"presets"`
}

type PingResponse struct {
	ID      string      `json:"id"`
	Type    MessageType `json:"type"`
	Version string      `json:"version"`
}

func NewResponse(reqID string) *Response {
	return &Response{
		ID:   reqID,
		Type: TypeResponse,
	}
}

func NewErrorResponse(reqID string, code string, message string) *Response {
	return &Response{
		ID:   reqID,
		Type: TypeError,
		Error: &ErrorInfo{
			Code:    code,
			Message: message,
		},
	}
}

func NewSessionResponse(reqID string, sessionID string) *SessionCreateResponse {
	return &SessionCreateResponse{
		ID:      reqID,
		Type:    TypeSessionCreate,
		Session: sessionID,
	}
}

const (
	ErrCodeTimeout           = "TIMEOUT"
	ErrCodeConnectionRefused = "CONNECTION_REFUSED"
	ErrCodeDNSFailure        = "DNS_FAILURE"
	ErrCodeTLSFailure        = "TLS_FAILURE"
	ErrCodeInvalidURL        = "INVALID_URL"
	ErrCodeInvalidSession    = "INVALID_SESSION"
	ErrCodeInvalidRequest    = "INVALID_REQUEST"
	ErrCodeInternal          = "INTERNAL_ERROR"
)
