package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/client"
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
	fmt.Println("Example 1: Basic Proxy Switching")
	fmt.Println(strings.Repeat("-", 60))

	c := client.NewClient("chrome-latest", client.WithTimeout(30*time.Second))
	defer c.Close()

	resp, err := c.Get(ctx, TEST_URL, nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ := resp.Text()
	trace := parseTrace(body)
	fmt.Println("Direct connection:")
	fmt.Printf("  Protocol: %s, IP: %s, Colo: %s\n", resp.Protocol, trace["ip"], trace["colo"])

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: Getting Current Proxy Configuration")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Printf("Current proxy: '%s' (empty = direct)\n", c.GetProxy())
	fmt.Printf("TCP proxy: '%s'\n", c.GetTCPProxy())
	fmt.Printf("UDP proxy: '%s'\n", c.GetUDPProxy())

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 3: Split Proxy Configuration (TCP vs UDP)")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`

c := client.NewClient("chrome-latest")
defer c.Close()

c.SetTCPProxy("http://tcp-proxy.example.com:8080")

c.SetUDPProxy("socks5://udp-proxy.example.com:1080")

fmt.Printf("TCP proxy: %s\n", c.GetTCPProxy())
fmt.Printf("UDP proxy: %s\n", c.GetUDPProxy())
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 4: HTTP/3 Proxy Switching")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`

c := client.NewClient("chrome-latest", client.WithForceHTTP3())
defer c.Close()

resp, _ := c.Get(ctx, "https://example.com", nil)
fmt.Printf("Direct: %s\n", resp.Protocol)

c.SetUDPProxy("socks5://user:pass@proxy.example.com:1080")
resp, _ = c.Get(ctx, "https://example.com", nil)
fmt.Printf("Via SOCKS5: %s\n", resp.Protocol)

c.SetUDPProxy("https://user:pass@brd.superproxy.io:10001")
resp, _ = c.Get(ctx, "https://example.com", nil)
fmt.Printf("Via MASQUE: %s\n", resp.Protocol)
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 5: Proxy Rotation Pattern")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`

proxies := []string{
    "http://proxy1.example.com:8080",
    "http://proxy2.example.com:8080",
    "http://proxy3.example.com:8080",
}

c := client.NewClient("chrome-latest")
defer c.Close()

for i, proxy := range proxies {
    c.SetProxy(proxy)
    resp, _ := c.Get(ctx, "https://api.ipify.org", nil)
    body, _ := resp.Text()
    fmt.Printf("Request %d via %s: IP = %s\n", i+1, proxy, body)
}
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Proxy switching examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}
