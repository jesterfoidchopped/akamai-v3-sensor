package client

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	http "github.com/sardanioss/http"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/klauspost/compress/zstd"
)

type StreamResponse struct {
	StatusCode    int
	Headers       map[string][]string
	FinalURL      string
	Timing        *protocol.Timing
	Protocol      string
	ContentLength int64 // -1 if unknown (chunked encoding)

	Request *Request

	reader       io.ReadCloser
	decompressor io.Closer
	rawReader    io.ReadCloser

	cancel context.CancelFunc
}

func (r *StreamResponse) Read(p []byte) (n int, err error) {
	return r.reader.Read(p)
}

func (r *StreamResponse) Close() error {
	if r.cancel != nil {
		r.cancel()
	}
	if r.decompressor != nil {
		r.decompressor.Close()
	}
	return r.rawReader.Close()
}

func (r *StreamResponse) ReadAll() ([]byte, error) {
	defer r.Close()
	return io.ReadAll(r.reader)
}

func (r *StreamResponse) Scanner() *bufio.Scanner {
	return bufio.NewScanner(r.reader)
}

func (r *StreamResponse) Lines() <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(r.reader)
		for scanner.Scan() {
			ch <- scanner.Text()
		}
	}()
	return ch
}

func (r *StreamResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

func (c *Client) DoStream(ctx context.Context, req *Request) (*StreamResponse, error) {
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
			cancel()
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
		cancel()
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	normalizeRequestWithBody(httpReq, bodyBytes)

	applyModeHeaders(httpReq, c.preset, req, parsedURL, c.getHeaderOrder())

	auth := req.Auth
	if auth == nil {
		auth = c.auth
	}
	if auth != nil {
		if err := auth.Apply(httpReq); err != nil {
			cancel()
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

	var resp *http.Response
	var usedProtocol string
	timing := &protocol.Timing{}

	effectiveProtocol := req.ForceProtocol
	if effectiveProtocol == ProtocolAuto && c.config.ForceProtocol != ProtocolAuto {
		effectiveProtocol = c.config.ForceProtocol
	}

	switch effectiveProtocol {
	case ProtocolHTTP3:
		if c.config.Proxy != "" {
			cancel()
			return nil, fmt.Errorf("HTTP/3 cannot be used with proxy: QUIC uses UDP which cannot tunnel through HTTP proxies")
		}
		if c.quicManager == nil {
			cancel()
			return nil, fmt.Errorf("HTTP/3 is disabled (no QUIC manager available)")
		}
		resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("HTTP/3 failed: %w", err)
		}
	case ProtocolHTTP2:
		resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			cancel()
			return nil, err
		}
	case ProtocolHTTP1:
		resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("HTTP/1.1 failed: %w", err)
		}
	default:
		if useH3 {
			resp, usedProtocol, err = c.doHTTP3(ctx, host, port, httpReq, timing, startTime)
			if err != nil {
				c.markH3Failed(hostKey)
				resetRequestBody(httpReq, bodyBytes)

				resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
			}
		} else {
			resp, usedProtocol, err = c.doHTTP2(ctx, host, port, httpReq, timing, startTime)
		}

		if err != nil && c.shouldUseH1(hostKey) {
			c.markH2Failed(hostKey)
			resetRequestBody(httpReq, bodyBytes)

			resp, usedProtocol, err = c.doHTTP1(ctx, host, port, httpReq, timing, startTime)
		}

		if err != nil {
			cancel()
			return nil, err
		}
	}

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

	reader, decompressor := setupDecompressor(resp.Body, resp.Header.Get("Content-Encoding"))

	timing.FirstByte = float64(time.Since(startTime).Milliseconds())

	return &StreamResponse{
		StatusCode:    resp.StatusCode,
		Headers:       headers,
		FinalURL:      reqURL,
		Timing:        timing,
		Protocol:      usedProtocol,
		ContentLength: resp.ContentLength,
		Request:       req,
		reader:        reader,
		decompressor:  decompressor,
		rawReader:     resp.Body,
		cancel:        cancel,
	}, nil
}

func setupDecompressor(body io.ReadCloser, encoding string) (io.ReadCloser, io.Closer) {
	switch strings.ToLower(encoding) {
	case "gzip":
		reader, err := gzip.NewReader(body)
		if err != nil {
			return body, nil
		}
		return reader, reader
	case "br":
		return &brotliReadCloser{brotli.NewReader(body)}, nil
	case "zstd":
		decoder, err := zstd.NewReader(body)
		if err != nil {
			return body, nil
		}
		return &zstdReadCloser{decoder}, nil
	default:
		return body, nil
	}
}

type brotliReadCloser struct {
	reader *brotli.Reader
}

func (b *brotliReadCloser) Read(p []byte) (n int, err error) {
	return b.reader.Read(p)
}

func (b *brotliReadCloser) Close() error {
	return nil // brotli.Reader doesn't need closing
}

type zstdReadCloser struct {
	*zstd.Decoder
}

func (z *zstdReadCloser) Close() error {
	z.Decoder.Close()
	return nil
}

func (c *Client) GetStream(ctx context.Context, url string, headers map[string][]string) (*StreamResponse, error) {
	return c.DoStream(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

type SSEEvent struct {
	Event string
	Data  string
	ID    string
	Retry int
}

type SSEReader struct {
	scanner *bufio.Scanner
	resp    *StreamResponse
}

func NewSSEReader(resp *StreamResponse) *SSEReader {
	return &SSEReader{
		scanner: bufio.NewScanner(resp.reader),
		resp:    resp,
	}
}

func (r *SSEReader) Next() (*SSEEvent, error) {
	event := &SSEEvent{}
	var dataLines []string

	for r.scanner.Scan() {
		line := r.scanner.Text()

		if line == "" {
			if len(dataLines) > 0 {
				event.Data = strings.Join(dataLines, "\n")
				return event, nil
			}
			continue
		}

		if strings.HasPrefix(line, ":") {
			continue
		}

		colonIdx := strings.Index(line, ":")
		var field, value string
		if colonIdx == -1 {
			field = line
			value = ""
		} else {
			field = line[:colonIdx]
			value = line[colonIdx+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
		}

		switch field {
		case "event":
			event.Event = value
		case "data":
			dataLines = append(dataLines, value)
		case "id":
			event.ID = value
		case "retry":
			var retry int
			for _, c := range value {
				if c >= '0' && c <= '9' {
					retry = retry*10 + int(c-'0')
				} else {
					break
				}
			}
			event.Retry = retry
		}
	}

	if err := r.scanner.Err(); err != nil {
		return nil, err
	}

	if len(dataLines) > 0 {
		event.Data = strings.Join(dataLines, "\n")
		return event, nil
	}

	return nil, io.EOF
}

func (r *SSEReader) Close() error {
	return r.resp.Close()
}

func (r *SSEReader) Events() <-chan *SSEEvent {
	ch := make(chan *SSEEvent)
	go func() {
		defer close(ch)
		for {
			event, err := r.Next()
			if err != nil {
				return
			}
			ch <- event
		}
	}()
	return ch
}
