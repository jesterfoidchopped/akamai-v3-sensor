package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor"
)

const TEST_URL = "https://www.cloudflare.com/cdn-cgi/trace"

func parseTrace(body string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if idx := strings.Index(line, "="); idx != -1 {
			result[line[:idx]] = line[idx+1:]
		}
	}
	return result
}

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Example 1: Warmup (Browser Page Load)")
	fmt.Println(strings.Repeat("-", 60))

	session := sensor.NewSession("chrome-latest", sensor.WithSessionTimeout(30*time.Second))

	if err := session.Warmup(ctx, "https://www.cloudflare.com"); err != nil {
		fmt.Printf("Warmup error: %v\n", err)
		return
	}
	fmt.Println("Warmup complete - TLS tickets, cookies, and cache populated")

	resp, err := session.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ := resp.Text()
	trace := parseTrace(body)
	fmt.Printf("Follow-up request: Protocol=%s, IP=%s\n", resp.Protocol, trace["ip"])

	session.Close()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: Fork (Parallel Browser Tabs)")
	fmt.Println(strings.Repeat("-", 60))

	session = sensor.NewSession("chrome-latest", sensor.WithSessionTimeout(30*time.Second))

	if err := session.Warmup(ctx, "https://www.cloudflare.com"); err != nil {
		fmt.Printf("Warmup error: %v\n", err)
		return
	}
	fmt.Println("Parent session warmed up")

	tabs := session.Fork(3)
	fmt.Printf("Forked into %d tabs\n", len(tabs))

	type result struct {
		index    int
		protocol string
		ip       string
	}
	results := make([]result, len(tabs))
	var wg sync.WaitGroup

	for i, tab := range tabs {
		wg.Add(1)
		go func(t *sensor.Session, idx int) {
			defer wg.Done()
			r, err := t.Get(ctx, TEST_URL)
			if err != nil {
				fmt.Printf("Tab %d error: %v\n", idx, err)
				return
			}
			b, _ := r.Text()
			tr := parseTrace(b)
			results[idx] = result{idx, r.Protocol, tr["ip"]}
		}(tab, i)
	}
	wg.Wait()

	for _, r := range results {
		fmt.Printf("  Tab %d: Protocol=%s, IP=%s\n", r.index, r.protocol, r.ip)
	}

	for _, tab := range tabs {
		tab.Close()
	}
	session.Close()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 3: Warmup + Fork (Recommended Pattern)")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
The recommended pattern for parallel scraping:

1. Create one session
2. Warmup to establish TLS tickets and cookies
3. Fork into N parallel sessions
4. Use each fork for independent requests

    session := sensor.NewSession("chrome-latest")
    session.Warmup(ctx, "https://example.com")

    tabs := session.Fork(10)
    var wg sync.WaitGroup
    for i, tab := range tabs {
        wg.Add(1)
        go func(t *sensor.Session, n int) {
            defer wg.Done()
            t.Get(ctx, fmt.Sprintf("https://example.com/page/%d", n))
        }(tab, i)
    }
    wg.Wait()

All forks share the same TLS fingerprint, cookies, and TLS session
cache (for 0-RTT resumption), but have independent TCP/QUIC connections.
This looks exactly like a single browser with multiple tabs.
`)

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Warmup & Fork examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}
