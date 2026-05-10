package main

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor"
)

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("QUIC Idle Timeout Configuration Examples")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("\n[1] Default QUIC Idle Timeout")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest", sensor.WithHTTPVersion("h3"))
	defer session.Close()

	resp, err := session.Get(ctx, "https://cloudflare.com", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	fmt.Println("Default idle timeout: 30 seconds")
	fmt.Println("Default keepalive: 15 seconds (half of idle timeout)")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[2] Extended QUIC Idle Timeout (2 minutes)")
	fmt.Println(strings.Repeat("-", 50))

	extendedSession := sensor.NewSession(
		"chrome-latest",
		sensor.WithHTTPVersion("h3"),
		sensor.WithQuicIdleTimeout(120*time.Second), // 2 minutes
	)
	defer extendedSession.Close()

	resp, err = extendedSession.Get(ctx, "https://cloudflare.com", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	fmt.Println("Custom idle timeout: 120 seconds")
	fmt.Println("Custom keepalive: 60 seconds (half of idle timeout)")

	fmt.Println("\nSimulating 5 second idle period...")
	time.Sleep(5 * time.Second)

	resp, err = extendedSession.Get(ctx, "https://cloudflare.com", nil)
	if err != nil {
		fmt.Printf("Error after idle: %v\n", err)
		return
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("After idle - Status: %d, Protocol: %s\n", resp.StatusCode, resp.Proto)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[3] Very Long Idle Timeout (5 minutes)")
	fmt.Println(strings.Repeat("-", 50))

	longSession := sensor.NewSession(
		"chrome-latest",
		sensor.WithHTTPVersion("h3"),
		sensor.WithQuicIdleTimeout(300*time.Second), // 5 minutes
	)
	defer longSession.Close()

	resp, err = longSession.Get(ctx, "https://cloudflare.com", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	fmt.Println("Custom idle timeout: 300 seconds (5 minutes)")
	fmt.Println("Custom keepalive: 150 seconds (2.5 minutes)")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[4] Combined with Other Options")
	fmt.Println(strings.Repeat("-", 50))

	combinedSession := sensor.NewSession(
		"chrome-latest",
		sensor.WithHTTPVersion("h3"),
		sensor.WithQuicIdleTimeout(180*time.Second), // 3 minutes
		sensor.WithTimeout(60*time.Second),          // Request timeout
		sensor.WithRetry(3),                         // Retry count
	)
	defer combinedSession.Close()

	resp, err = combinedSession.Get(ctx, "https://cloudflare.com", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Printf("Status: %d\n", resp.StatusCode)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	fmt.Println("QUIC idle timeout: 180s, Request timeout: 60s, Retries: 3")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("When to Adjust QUIC Idle Timeout")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(`
Use HIGHER idle timeout (60-300s) when:
  - Your app keeps connections pooled for reuse
  - Making periodic requests with gaps > 30 seconds
  - Using long polling or server-sent events over HTTP/3
  - Experiencing "connection closed" errors after idle periods

Use DEFAULT idle timeout (30s) when:
  - Making quick, one-off requests
  - Request patterns have < 30 second gaps
  - Memory is constrained (longer timeouts = more memory)

Note: The keepalive is automatically set to half of idle timeout.
This ensures keepalive packets are sent before the connection
would otherwise be closed due to inactivity.
`)
}
