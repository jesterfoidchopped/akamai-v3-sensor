package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	http "github.com/sardanioss/http"
	"net/url"
)

type PreparedRequest struct {
	HTTPRequest *http.Request

	Method  string
	URL     string
	Headers map[string][]string
	Body    []byte // Cached body bytes

	Timeout       int64    // Timeout in milliseconds
	ForceProtocol Protocol // Forced protocol
	FetchMode     FetchMode
	FetchSite     FetchSite
	FetchDest     string
	Referer       string
	Auth          Auth

	FollowRedirects bool
	MaxRedirects    int

	client *Client

	prepared bool
}

func (c *Client) Prepare(ctx context.Context, req *Request) (*PreparedRequest, error) {
	reqURL := req.URL
	if len(req.Params) > 0 {
		reqURL = NewURLBuilder(req.URL).Params(req.Params).Build()
	}

	parsedURL, err := url.Parse(reqURL)
	if err != nil {
		return nil, err
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
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
		return nil, err
	}

	normalizeRequestWithBody(httpReq, bodyBytes)

	for key, value := range c.preset.Headers {
		httpReq.Header.Set(key, value)
	}

	userAgent := c.preset.UserAgent
	if req.UserAgent != "" {
		userAgent = req.UserAgent
	}
	httpReq.Header.Set("User-Agent", userAgent)

	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}

	applyModeHeaders(httpReq, c.preset, req, parsedURL, c.getHeaderOrder())

	if c.cookies != nil {
		cookieHeader := c.cookies.CookieHeader(parsedURL)
		if cookieHeader != "" {
			httpReq.Header.Set("Cookie", cookieHeader)
		}
	}

	followRedirects := c.config.FollowRedirects
	if req.FollowRedirects != nil {
		followRedirects = *req.FollowRedirects
	}
	maxRedirects := c.config.MaxRedirects
	if req.MaxRedirects > 0 {
		maxRedirects = req.MaxRedirects
	}

	return &PreparedRequest{
		HTTPRequest:     httpReq,
		Method:          method,
		URL:             reqURL,
		Headers:         req.Headers,
		Body:            bodyBytes,
		Timeout:         int64(req.Timeout.Milliseconds()),
		ForceProtocol:   req.ForceProtocol,
		FetchMode:       req.FetchMode,
		FetchSite:       req.FetchSite,
		FetchDest:       req.FetchDest,
		Referer:         req.Referer,
		Auth:            req.Auth,
		FollowRedirects: followRedirects,
		MaxRedirects:    maxRedirects,
		client:          c,
		prepared:        true,
	}, nil
}

func (p *PreparedRequest) SetHeader(key, value string) *PreparedRequest {
	p.HTTPRequest.Header.Set(key, value)
	return p
}

func (p *PreparedRequest) AddHeader(key, value string) *PreparedRequest {
	p.HTTPRequest.Header.Add(key, value)
	return p
}

func (p *PreparedRequest) DelHeader(key string) *PreparedRequest {
	p.HTTPRequest.Header.Del(key)
	return p
}

func (p *PreparedRequest) GetHeader(key string) string {
	return p.HTTPRequest.Header.Get(key)
}

func (p *PreparedRequest) GetAllHeaders() http.Header {
	return p.HTTPRequest.Header
}

func (p *PreparedRequest) SetBody(body []byte) *PreparedRequest {
	p.Body = body
	p.HTTPRequest.Body = io.NopCloser(bytes.NewReader(body))
	p.HTTPRequest.ContentLength = int64(len(body))
	p.HTTPRequest.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return p
}

func (p *PreparedRequest) SetAuth(auth Auth) *PreparedRequest {
	p.Auth = auth
	return p
}

func (p *PreparedRequest) SetTimeout(ms int64) *PreparedRequest {
	p.Timeout = ms
	return p
}

func (p *PreparedRequest) SetForceProtocol(protocol Protocol) *PreparedRequest {
	p.ForceProtocol = protocol
	return p
}

func (p *PreparedRequest) Send(ctx context.Context) (*Response, error) {
	if !p.prepared {
		return nil, &RequestError{Op: "send", Err: "request not prepared"}
	}

	auth := p.Auth
	if auth == nil {
		auth = p.client.auth
	}
	if auth != nil {
		if err := auth.Apply(p.HTTPRequest); err != nil {
			return nil, err
		}
	}

	var bodyReader io.Reader
	if len(p.Body) > 0 {
		bodyReader = bytes.NewReader(p.Body)
	}
	req := &Request{
		Method:          p.Method,
		URL:             p.URL,
		Headers:         p.Headers,
		Body:            bodyReader,
		Timeout:         time.Duration(p.Timeout) * time.Millisecond, // Convert ms back to Duration
		ForceProtocol:   p.ForceProtocol,
		FetchMode:       p.FetchMode,
		FetchSite:       p.FetchSite,
		FetchDest:       p.FetchDest,
		Referer:         p.Referer,
		Auth:            p.Auth,
		FollowRedirects: &p.FollowRedirects,
		MaxRedirects:    p.MaxRedirects,
	}

	return p.client.Do(ctx, req)
}

type RequestError struct {
	Op  string
	Err string
}

func (e *RequestError) Error() string {
	return e.Op + ": " + e.Err
}

func (c *Client) PrepareGet(ctx context.Context, url string, headers map[string][]string) (*PreparedRequest, error) {
	return c.Prepare(ctx, &Request{
		Method:  "GET",
		URL:     url,
		Headers: headers,
	})
}

func (c *Client) PreparePost(ctx context.Context, url string, body io.Reader, headers map[string][]string) (*PreparedRequest, error) {
	return c.Prepare(ctx, &Request{
		Method:  "POST",
		URL:     url,
		Body:    body,
		Headers: headers,
	})
}
