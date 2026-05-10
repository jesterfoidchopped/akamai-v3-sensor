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
	"github.com/jesterfoidchopped/akamai-v3-sensor/pool"
	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/klauspost/compress/zstd"
)

type HTTP3Client struct {
	quicManager *pool.QUICManager
	preset      *fingerprint.Preset
	timeout     time.Duration
}

func NewHTTP3Client(presetName string) *HTTP3Client {
	preset := fingerprint.Get(presetName)
	h2Manager := pool.NewManager(preset)

	return &HTTP3Client{
		quicManager: pool.NewQUICManager(preset, h2Manager.GetDNSCache()),
		preset:      preset,
		timeout:     30 * time.Second,
	}
}

func NewHTTP3ClientWithDNS(presetName string, dnsCache interface{}) *HTTP3Client {
	preset := fingerprint.Get(presetName)

	var quicMgr *pool.QUICManager
	if dc, ok := dnsCache.(*pool.Manager); ok {
		quicMgr = pool.NewQUICManager(preset, dc.GetDNSCache())
	} else {
		h2Manager := pool.NewManager(preset)
		quicMgr = pool.NewQUICManager(preset, h2Manager.GetDNSCache())
	}

	return &HTTP3Client{
		quicManager: quicMgr,
		preset:      preset,
		timeout:     30 * time.Second,
	}
}

func (c *HTTP3Client) SetPreset(presetName string) {
	c.preset = fingerprint.Get(presetName)
}

func (c *HTTP3Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

func (c *HTTP3Client) Do(ctx context.Context, req *Request) (*Response, error) {
	startTime := time.Now()

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	if parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("HTTP/3 only supports HTTPS")
	}

	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	timeout := c.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	timing := &protocol.Timing{}
	connStart := time.Now()

	conn, err := c.quicManager.GetConn(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("failed to get QUIC connection: %w", err)
	}

	if conn.UseCount == 1 {
		connTime := float64(time.Since(connStart).Milliseconds())
		timing.DNSLookup = connTime / 3
		timing.TCPConnect = 0                  // QUIC doesn't use TCP
		timing.TLSHandshake = connTime * 2 / 3 // QUIC combines connection + TLS
	} else {
		timing.DNSLookup = 0
		timing.TCPConnect = 0
		timing.TLSHandshake = 0
	}

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

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	normalizeRequestWithBody(httpReq, bodyBytes)

	for key, value := range c.preset.Headers {
		httpReq.Header.Set(key, value)
	}

	httpReq.Header.Set("User-Agent", c.preset.UserAgent)

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

	firstByteTime := time.Now()
	resp, err := conn.HTTP3RT.RoundTrip(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP/3 request failed: %w", err)
	}
	defer resp.Body.Close()

	timing.FirstByte = float64(time.Since(firstByteTime).Milliseconds())

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	contentEncoding := resp.Header.Get("Content-Encoding")
	body, err = decompressHTTP3(body, contentEncoding)
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
		FinalURL:   req.URL,
		Timing:     timing,
		bodyBytes:  body,
		bodyRead:   true,
	}, nil
}

func (c *HTTP3Client) Get(ctx context.Context, url string, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

func (c *HTTP3Client) Post(ctx context.Context, url string, body io.Reader, headers map[string][]string) (*Response, error) {
	return c.Do(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}

func (c *HTTP3Client) Close() {
	c.quicManager.Close()
}

func (c *HTTP3Client) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	return c.quicManager.Stats()
}

func decompressHTTP3(data []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(encoding) {
	case "br":
		reader := brotli.NewReader(bytes.NewReader(data))
		return io.ReadAll(reader)

	case "gzip":
		return decompressGzip(data)

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

func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
