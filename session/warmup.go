package session

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
	"golang.org/x/net/html"
)

type resourceType int

const (
	resourceCSS resourceType = iota
	resourceJS
	resourceImage
	resourceFont
)

type subresource struct {
	url string
	typ resourceType
}

const maxSubresources = 50

const concurrencyLimit = 6

func (s *Session) Warmup(ctx context.Context, url string) error {
	resp, err := s.Request(ctx, &transport.Request{
		Method: "GET",
		URL:    url,
	})
	if err != nil {
		return err
	}

	body, err := resp.Bytes()
	if err != nil {
		return err
	}

	ct := ""
	if vals, ok := resp.Headers["content-type"]; ok && len(vals) > 0 {
		ct = vals[0]
	}
	if !strings.Contains(ct, "text/html") {
		return nil
	}

	resources := parseSubresources(body, url)

	cssAndFonts, scripts, images := groupByPriority(resources)

	pageURL := resp.FinalURL
	if pageURL == "" {
		pageURL = url
	}

	batches := [][]subresource{cssAndFonts, scripts, images}
	delays := []struct{ min, max int }{{0, 0}, {50, 150}, {100, 300}}

	for i, batch := range batches {
		if len(batch) == 0 {
			continue
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if i > 0 && delays[i].max > 0 {
			if err := interBatchDelay(ctx, delays[i].min, delays[i].max); err != nil {
				return err
			}
		}

		fetchBatch(ctx, s, batch, pageURL)
	}

	return nil
}

func parseSubresources(body []byte, baseURL string) []subresource {
	tokenizer := html.NewTokenizer(strings.NewReader(string(body)))
	seen := make(map[string]bool)
	var resources []subresource

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		tn, hasAttr := tokenizer.TagName()
		if !hasAttr {
			continue
		}
		tagName := string(tn)

		switch tagName {
		case "link":
			href, rel, as := parseLinkAttrs(tokenizer)
			if href == "" {
				continue
			}
			var typ resourceType
			var matched bool
			switch rel {
			case "stylesheet":
				typ = resourceCSS
				matched = true
			case "icon":
				typ = resourceImage
				matched = true
			case "preload":
				matched = true
				switch as {
				case "style":
					typ = resourceCSS
				case "script":
					typ = resourceJS
				case "image":
					typ = resourceImage
				case "font":
					typ = resourceFont
				default:
					matched = false
				}
			}
			if matched {
				resolved := resolveURL(baseURL, href)
				if !seen[resolved] {
					seen[resolved] = true
					resources = append(resources, subresource{url: resolved, typ: typ})
				}
			}

		case "script":
			src := getAttr(tokenizer, "src")
			if src != "" {
				resolved := resolveURL(baseURL, src)
				if !seen[resolved] {
					seen[resolved] = true
					resources = append(resources, subresource{url: resolved, typ: resourceJS})
				}
			}

		case "img":
			src := getAttr(tokenizer, "src")
			if src != "" {
				resolved := resolveURL(baseURL, src)
				if !seen[resolved] {
					seen[resolved] = true
					resources = append(resources, subresource{url: resolved, typ: resourceImage})
				}
			}
		}

		if len(resources) >= maxSubresources {
			break
		}
	}

	return resources
}

func parseLinkAttrs(z *html.Tokenizer) (href, rel, as string) {
	for {
		key, val, more := z.TagAttr()
		k := string(key)
		switch k {
		case "href":
			href = string(val)
		case "rel":
			rel = strings.ToLower(string(val))
		case "as":
			as = strings.ToLower(string(val))
		}
		if !more {
			break
		}
	}
	return
}

func getAttr(z *html.Tokenizer, name string) string {
	for {
		key, val, more := z.TagAttr()
		if string(key) == name {
			return string(val)
		}
		if !more {
			break
		}
	}
	return ""
}

func groupByPriority(resources []subresource) (cssAndFonts, scripts, images []subresource) {
	for _, r := range resources {
		switch r.typ {
		case resourceCSS, resourceFont:
			cssAndFonts = append(cssAndFonts, r)
		case resourceJS:
			scripts = append(scripts, r)
		case resourceImage:
			images = append(images, r)
		}
	}
	return
}

func fetchBatch(ctx context.Context, s *Session, batch []subresource, pageURL string) {
	sem := make(chan struct{}, concurrencyLimit)
	var wg sync.WaitGroup

	for _, res := range batch {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(r subresource) {
			defer wg.Done()
			defer func() { <-sem }() // release

			if ctx.Err() != nil {
				return
			}

			headers := buildSubresourceHeaders(r.typ, pageURL, r.url)
			req := &transport.Request{
				Method:  "GET",
				URL:     r.url,
				Headers: headers,
			}

			resp, err := s.Request(ctx, req)
			if err != nil {
				return
			}
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}(res)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func buildSubresourceHeaders(typ resourceType, pageURL, targetURL string) map[string][]string {
	var reqCtx fingerprint.RequestContext
	var accept, priority string

	switch typ {
	case resourceCSS:
		reqCtx = fingerprint.StyleContext(pageURL, targetURL)
		accept = "text/css,*/*;q=0.1"
		priority = "u=0, i"
	case resourceJS:
		reqCtx = fingerprint.ScriptContext(pageURL, targetURL)
		accept = "*/*"
		priority = "u=1"
	case resourceImage:
		reqCtx = fingerprint.ImageContext(pageURL, targetURL)
		accept = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
		priority = "u=2"
	case resourceFont:
		reqCtx = fingerprint.FontContext(pageURL, targetURL)
		accept = "*/*"
		priority = "u=3"
	}

	secFetch := fingerprint.GenerateSecFetchHeaders(reqCtx)

	headers := map[string][]string{
		"Accept":         {accept},
		"Sec-Fetch-Site": {secFetch.Site},
		"Sec-Fetch-Mode": {secFetch.Mode},
		"Sec-Fetch-Dest": {secFetch.Dest},
		"Referer":        {pageURL},
		"Priority":       {priority},
	}

	return headers
}

func interBatchDelay(ctx context.Context, minMs, maxMs int) error {
	d := time.Duration(minMs) * time.Millisecond
	if maxMs > minMs {
		d += time.Duration(randInt64(int64(maxMs-minMs))) * time.Millisecond
	}
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
