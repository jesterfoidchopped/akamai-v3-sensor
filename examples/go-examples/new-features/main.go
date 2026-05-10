package main

import (
	"context"
	"fmt"
	"os"
	"strings"
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
	fmt.Println("Example 1: Refresh (Browser Page Refresh)")
	fmt.Println(strings.Repeat("-", 60))

	session := sensor.NewSession("chrome-latest", sensor.WithSessionTimeout(30*time.Second))

	resp, err := session.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ := resp.Text()
	trace := parseTrace(body)
	fmt.Printf("First request: Protocol=%s, IP=%s\n", resp.Protocol, trace["ip"])

	session.Refresh()
	fmt.Println("Called Refresh() - connections closed, TLS cache kept")

	resp, err = session.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	body, _ = resp.Text()
	trace = parseTrace(body)
	fmt.Printf("After refresh: Protocol=%s, IP=%s (TLS resumption)\n", resp.Protocol, trace["ip"])

	session.Close()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 2: TLS Key Logging")
	fmt.Println(strings.Repeat("-", 60))

	keylogPath := "/tmp/go_keylog_example.txt"

	os.Remove(keylogPath)

	session2 := sensor.NewSession("chrome-latest",
		sensor.WithSessionTimeout(30*time.Second),
		sensor.WithKeyLogFile(keylogPath),
	)

	resp, err = session2.Get(ctx, TEST_URL)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Request completed: Protocol=%s\n", resp.Protocol)

	session2.Close()

	if info, err := os.Stat(keylogPath); err == nil {
		fmt.Printf("Key log file created: %s (%d bytes)\n", keylogPath, info.Size())
		fmt.Println("Use in Wireshark: Edit -> Preferences -> Protocols -> TLS -> Pre-Master-Secret log filename")
	} else {
		fmt.Println("Key log file not found")
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 3: Local Address Binding")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
Local address binding allows you to specify which local IP to use
for outgoing connections. This is essential for IPv6 rotation scenarios.

Usage:

session, _ := sensor.NewSession("chrome-latest",
    sensor.WithLocalAddress("2001:db8::1"),
)

session, _ := sensor.NewSession("chrome-latest",
    sensor.WithLocalAddress("192.168.1.100"),
)

Note: When local address is set, target IPs are filtered to match
the address family (IPv6 local -> only connects to IPv6 targets).

Example with your machine's IPs:
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example 4: Speculative TLS for Proxy Connections")
	fmt.Println(strings.Repeat("-", 60))

	fmt.Println(`
Speculative TLS (disabled by default):
Sends CONNECT + TLS ClientHello together, saving one round-trip (~25% faster).
Enable it if your proxy supports it and you want the extra speed:

session := sensor.NewSession("chrome-latest",
    sensor.WithProxy("http://user:pass@proxy.example.com:8080"),
    sensor.WithEnableSpeculativeTLS(),
)
`)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("New features examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}
