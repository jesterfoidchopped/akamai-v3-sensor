package transport

import (
	"errors"
	"fmt"
	"net"
	"strings"

	utls "github.com/sardanioss/utls"
)

var (
	ErrConnection = errors.New("connection error")

	ErrTLS = errors.New("TLS error")

	ErrDNS = errors.New("DNS error")

	ErrTimeout = errors.New("timeout error")

	ErrProxy = errors.New("proxy error")

	ErrProtocol = errors.New("protocol error")

	ErrRequest = errors.New("request error")

	ErrResponse = errors.New("response error")

	ErrClosed = errors.New("transport closed")

	ErrALPNMismatch = errors.New("ALPN mismatch")
)

type ALPNMismatchError struct {
	Expected   string      // Expected protocol (e.g., "h2")
	Negotiated string      // Actually negotiated protocol (e.g., "http/1.1")
	TLSConn    *utls.UConn // The TLS connection (caller should close if not reusing)
	Host       string      // Target host
	Port       string      // Target port
}

func (e *ALPNMismatchError) Error() string {
	return fmt.Sprintf("ALPN mismatch: expected %s, got %s", e.Expected, e.Negotiated)
}

func (e *ALPNMismatchError) Unwrap() error {
	return ErrALPNMismatch
}

type TransportError struct {
	Op        string // Operation that failed (e.g., "dial", "tls_handshake", "request")
	Host      string // Target host
	Port      string // Target port
	Protocol  string // Protocol (h1, h2, h3)
	Cause     error  // Underlying error
	Category  error  // Error category (ErrConnection, ErrTLS, etc.)
	Retryable bool   // Whether the operation can be retried
}

func (e *TransportError) Error() string {
	var sb strings.Builder
	sb.WriteString(e.Op)
	if e.Host != "" {
		sb.WriteString(" ")
		sb.WriteString(e.Host)
		if e.Port != "" && e.Port != "443" && e.Port != "80" {
			sb.WriteString(":")
			sb.WriteString(e.Port)
		}
	}
	if e.Protocol != "" {
		sb.WriteString(" [")
		sb.WriteString(e.Protocol)
		sb.WriteString("]")
	}
	if e.Cause != nil {
		sb.WriteString(": ")
		sb.WriteString(e.Cause.Error())
	}
	return sb.String()
}

func (e *TransportError) Unwrap() error {
	return e.Cause
}

func (e *TransportError) Is(target error) bool {
	if e.Category != nil && errors.Is(e.Category, target) {
		return true
	}
	return errors.Is(e.Cause, target)
}

func (e *TransportError) IsRetryable() bool {
	return e.Retryable
}

func NewConnectionError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrConnection,
		Retryable: isRetryableError(cause),
	}
}

func NewTLSError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrTLS,
		Retryable: false, // TLS errors are generally not retryable
	}
}

func NewDNSError(host string, cause error) *TransportError {
	return &TransportError{
		Op:        "dns_resolve",
		Host:      host,
		Cause:     cause,
		Category:  ErrDNS,
		Retryable: true, // DNS failures can be transient
	}
}

func NewTimeoutError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrTimeout,
		Retryable: true, // Timeouts are retryable
	}
}

func NewProxyError(op, host, port string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Cause:     cause,
		Category:  ErrProxy,
		Retryable: false,
	}
}

func NewProtocolError(host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        "protocol_negotiation",
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrProtocol,
		Retryable: false,
	}
}

func NewRequestError(op, host, port, protocol string, cause error) *TransportError {
	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  ErrRequest,
		Retryable: isRetryableError(cause),
	}
}

func WrapError(op, host, port, protocol string, cause error) error {
	if cause == nil {
		return nil
	}

	var te *TransportError
	if errors.As(cause, &te) {
		return cause
	}

	category := categorizeError(cause)
	retryable := isRetryableError(cause)

	return &TransportError{
		Op:        op,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Cause:     cause,
		Category:  category,
		Retryable: retryable,
	}
}

func categorizeError(err error) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return ErrTimeout
	}

	if _, ok := err.(*net.DNSError); ok {
		return ErrDNS
	}

	if strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "x509") ||
		strings.Contains(errStr, "handshake") {
		return ErrTLS
	}

	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network is unreachable") {
		return ErrConnection
	}

	if strings.Contains(errStr, "proxy") {
		return ErrProxy
	}

	if strings.Contains(errStr, "protocol") ||
		strings.Contains(errStr, "http2") ||
		strings.Contains(errStr, "alpn") {
		return ErrProtocol
	}

	return ErrConnection
}

func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}

	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return true
	}

	errStr := strings.ToLower(err.Error())

	if strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "broken pipe") {
		return true
	}

	if _, ok := err.(*net.DNSError); ok {
		return true
	}

	if strings.Contains(errStr, "eof") {
		return true
	}

	return false
}

func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrTimeout)
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func IsTLSError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrTLS)
	}
	return strings.Contains(strings.ToLower(err.Error()), "tls")
}

func IsDNSError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrDNS)
	}
	_, ok := err.(*net.DNSError)
	return ok
}

func IsConnectionError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrConnection)
	}
	return false
}

func IsProxyError(err error) bool {
	if err == nil {
		return false
	}
	var te *TransportError
	if errors.As(err, &te) {
		return errors.Is(te.Category, ErrProxy)
	}
	return strings.Contains(strings.ToLower(err.Error()), "proxy")
}

type HTTPError struct {
	StatusCode int
	Status     string
	Body       []byte
	Headers    map[string]string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Status)
}

func (e *HTTPError) IsClientError() bool {
	return e.StatusCode >= 400 && e.StatusCode < 500
}

func (e *HTTPError) IsServerError() bool {
	return e.StatusCode >= 500
}

func (e *HTTPError) IsRetryable() bool {
	switch e.StatusCode {
	case 408, 425, 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

func NewHTTPError(statusCode int, status string, body []byte, headers map[string]string) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Body:       body,
		Headers:    headers,
	}
}
