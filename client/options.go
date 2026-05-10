package client

import (
	"crypto/tls"
	"time"
)

type ClientConfig struct {
	Preset string

	Timeout time.Duration

	Proxy string

	TCPProxy string

	UDPProxy string

	FollowRedirects bool

	MaxRedirects int

	RetryEnabled bool

	MaxRetries int

	RetryWaitMin time.Duration

	RetryWaitMax time.Duration

	RetryOnStatus []int

	InsecureSkipVerify bool

	TLSConfig *tls.Config

	DisableKeepAlives bool

	DisableH3 bool

	PreferIPv4 bool

	ConnectTo map[string]string

	ECHConfig []byte

	ECHConfigDomain string

	DisableECH bool

	ForceProtocol Protocol

	TLSOnly bool
}

func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		Preset:             "chrome-latest",
		Timeout:            30 * time.Second,
		FollowRedirects:    true,
		MaxRedirects:       10,
		RetryEnabled:       false,
		MaxRetries:         3,
		RetryWaitMin:       1 * time.Second,
		RetryWaitMax:       30 * time.Second,
		RetryOnStatus:      []int{429, 500, 502, 503, 504},
		InsecureSkipVerify: false,
		DisableKeepAlives:  false,
		DisableH3:          false,
	}
}

type Option func(*ClientConfig)

func WithPreset(preset string) Option {
	return func(c *ClientConfig) {
		c.Preset = preset
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(c *ClientConfig) {
		c.Timeout = timeout
	}
}

func WithProxy(proxyURL string) Option {
	return func(c *ClientConfig) {
		c.Proxy = proxyURL
	}
}

func WithTCPProxy(proxyURL string) Option {
	return func(c *ClientConfig) {
		c.TCPProxy = proxyURL
	}
}

func WithUDPProxy(proxyURL string) Option {
	return func(c *ClientConfig) {
		c.UDPProxy = proxyURL
	}
}

func WithRedirects(follow bool, maxRedirects int) Option {
	return func(c *ClientConfig) {
		c.FollowRedirects = follow
		c.MaxRedirects = maxRedirects
	}
}

func WithoutRedirects() Option {
	return func(c *ClientConfig) {
		c.FollowRedirects = false
	}
}

func WithRetry(maxRetries int) Option {
	return func(c *ClientConfig) {
		c.RetryEnabled = true
		c.MaxRetries = maxRetries
	}
}

func WithoutRetry() Option {
	return func(c *ClientConfig) {
		c.RetryEnabled = false
		c.MaxRetries = 0
	}
}

func WithRetryConfig(maxRetries int, waitMin, waitMax time.Duration, retryOnStatus []int) Option {
	return func(c *ClientConfig) {
		c.RetryEnabled = true
		c.MaxRetries = maxRetries
		c.RetryWaitMin = waitMin
		c.RetryWaitMax = waitMax
		if len(retryOnStatus) > 0 {
			c.RetryOnStatus = retryOnStatus
		}
	}
}

func WithInsecureSkipVerify() Option {
	return func(c *ClientConfig) {
		c.InsecureSkipVerify = true
	}
}

func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *ClientConfig) {
		c.TLSConfig = tlsConfig
	}
}

func WithDisableKeepAlives() Option {
	return func(c *ClientConfig) {
		c.DisableKeepAlives = true
	}
}

func WithDisableHTTP3() Option {
	return func(c *ClientConfig) {
		c.DisableH3 = true
	}
}

func WithForceHTTP2() Option {
	return func(c *ClientConfig) {
		c.ForceProtocol = ProtocolHTTP2
		c.DisableH3 = true // Also disable H3 for consistency
	}
}

type Protocol int

const (
	ProtocolAuto  Protocol = iota // Auto-detect (H3 -> H2 -> H1 fallback)
	ProtocolHTTP1                 // Force HTTP/1.1
	ProtocolHTTP2                 // Force HTTP/2
	ProtocolHTTP3                 // Force HTTP/3
)

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

func WithForceHTTP1() Option {
	return func(c *ClientConfig) {
		c.ForceProtocol = ProtocolHTTP1
		c.DisableH3 = true // Also disable H3 for consistency
	}
}

func WithForceHTTP3() Option {
	return func(c *ClientConfig) {
		c.ForceProtocol = ProtocolHTTP3
	}
}

func WithTLSOnly() Option {
	return func(c *ClientConfig) {
		c.TLSOnly = true
	}
}

func WithPreferIPv4() Option {
	return func(c *ClientConfig) {
		c.PreferIPv4 = true
	}
}

var WithDisableH3 = WithDisableHTTP3

func WithConnectTo(requestHost, connectHost string) Option {
	return func(c *ClientConfig) {
		if c.ConnectTo == nil {
			c.ConnectTo = make(map[string]string)
		}
		c.ConnectTo[requestHost] = connectHost
	}
}

func WithECHConfig(echConfig []byte) Option {
	return func(c *ClientConfig) {
		c.ECHConfig = echConfig
	}
}

func WithECHFrom(domain string) Option {
	return func(c *ClientConfig) {
		c.ECHConfigDomain = domain
	}
}

func WithDisableECH() Option {
	return func(c *ClientConfig) {
		c.DisableECH = true
	}
}

var EnableCookies = struct{}{}
