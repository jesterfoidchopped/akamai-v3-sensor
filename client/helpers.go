package client

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"fmt"
	http "github.com/sardanioss/http"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/klauspost/compress/zstd"
)

func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func parseURL(urlStr string) (*url.URL, error) {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("only HTTPS is supported")
	}
	return parsed, nil
}

func buildHTTPRequest(ctx context.Context, req *Request, preset *fingerprint.Preset, host string) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyBytes []byte
	var bodyReader io.Reader
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	normalizeRequestWithBody(httpReq, bodyBytes)

	for key, value := range preset.Headers {
		httpReq.Header.Set(key, value)
	}

	httpReq.Header.Set("User-Agent", preset.UserAgent)

	httpReq.Header.Set("Host", host)

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	return httpReq, nil
}

func processResponse(resp *http.Response, originalURL string, startTime time.Time, timing *protocol.Timing) (*Response, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = Decompress(body, contentEncoding)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress response: %w", err)
	}

	timing.Total = float64(time.Since(startTime).Milliseconds())

	headers := make(map[string][]string)
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		headerValues := make([]string, len(values))
		copy(headerValues, values)
		headers[lowerKey] = headerValues
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       io.NopCloser(bytes.NewReader(body)),
		FinalURL:   originalURL,
		Timing:     timing,
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

func Decompress(data []byte, encoding string) ([]byte, error) {
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

func normalizeRequest(req *http.Request, bodyLen int) {
	method := strings.ToUpper(req.Method)

	if bodyLen > 0 {
		req.ContentLength = int64(bodyLen)
		req.Header.Set("Content-Length", fmt.Sprintf("%d", bodyLen))
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		req.ContentLength = 0
		req.Header.Set("Content-Length", "0")
	}

	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}

	if method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE" {
		if bodyLen == 0 {
			req.Header.Del("Content-Length")
		}
	}
}

func normalizeRequestWithBody(req *http.Request, body []byte) {
	normalizeRequest(req, len(body))

	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		contentType := detectContentType(body)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
	}
}

func normalizeRequestWithReader(req *http.Request, body io.Reader) {
	if body == nil {
		normalizeRequest(req, 0)
		return
	}

	var bodyLen int64 = -1
	switch r := body.(type) {
	case *bytes.Reader:
		bodyLen = int64(r.Len())
	case *bytes.Buffer:
		bodyLen = int64(r.Len())
	case *strings.Reader:
		bodyLen = int64(r.Len())
	case io.Seeker:
		if cur, err := r.Seek(0, io.SeekCurrent); err == nil {
			if end, err := r.Seek(0, io.SeekEnd); err == nil {
				bodyLen = end - cur
				r.Seek(cur, io.SeekStart) // Reset position
			}
		}
	}

	if bodyLen >= 0 {
		normalizeRequest(req, int(bodyLen))
	} else {
		normalizeRequest(req, 0)
	}
}

func detectContentType(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 {
		first := trimmed[0]
		if first == '{' || first == '[' {
			if isLikelyJSON(trimmed) {
				return "application/json"
			}
		}
	}

	if len(trimmed) > 0 && trimmed[0] == '<' {
		if bytes.HasPrefix(trimmed, []byte("<?xml")) ||
			bytes.HasPrefix(trimmed, []byte("<soap")) ||
			bytes.HasPrefix(trimmed, []byte("<SOAP")) {
			return "application/xml"
		}
		if bytes.Contains(trimmed[:min(100, len(trimmed))], []byte("html")) {
			return "text/html"
		}
	}

	if isFormEncoded(trimmed) {
		return "application/x-www-form-urlencoded"
	}

	return ""
}

func isLikelyJSON(body []byte) bool {
	if len(body) < 2 {
		return false
	}
	first := body[0]
	last := body[len(body)-1]

	if first == '{' && last == '}' {
		return true
	}
	if first == '[' && last == ']' {
		return true
	}
	return false
}

func isFormEncoded(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	hasEquals := bytes.Contains(body, []byte("="))
	hasNewline := bytes.Contains(body, []byte("\n"))
	hasSpace := bytes.Contains(body, []byte(" "))

	return hasEquals && !hasNewline && !hasSpace
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hasBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func resetRequestBody(httpReq *http.Request, body []byte) {
	if len(body) > 0 {
		httpReq.Body = io.NopCloser(bytes.NewReader(body))
	} else if hasBody(httpReq.Method) {
		httpReq.Body = io.NopCloser(bytes.NewReader([]byte{}))
	}
}
