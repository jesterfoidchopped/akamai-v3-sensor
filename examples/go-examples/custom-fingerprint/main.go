package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jesterfoidchopped/akamai-v3-sensor"
)

const chrome131JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172" +
	"-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-65037,29-23-24,0"

const chromeAkamai = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"

func main() {
	ctx := context.Background()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Custom JA3 & Akamai Fingerprint Examples")
	fmt.Println(strings.Repeat("=", 60))

	example1CustomJA3(ctx)
	example2CustomAkamai(ctx)
	example3Combined(ctx)
	example4ExtraOptions(ctx)
	printSummary()
}

func example1CustomJA3(ctx context.Context) {
	fmt.Println("\n[1] Custom JA3 Fingerprint")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest",
		sensor.WithCustomFingerprint(sensor.CustomFingerprint{
			JA3: chrome131JA3,
		}),
	)
	defer session.Close()

	resp, err := session.Get(ctx, "https://tls.peet.ws/api/tls")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		TLS struct {
			JA3Hash string `json:"ja3_hash"`
			JA3     string `json:"ja3"`
		} `json:"tls"`
	}
	json.Unmarshal(body, &result)

	fmt.Printf("JA3 hash: %s\n", result.TLS.JA3Hash)
	if len(result.TLS.JA3) > 80 {
		fmt.Printf("JA3 text: %s...\n", result.TLS.JA3[:80])
	} else {
		fmt.Printf("JA3 text: %s\n", result.TLS.JA3)
	}
	fmt.Println("\nThe TLS fingerprint now matches the custom JA3 string,")
	fmt.Println("not the chrome-latest preset.")
}

func example2CustomAkamai(ctx context.Context) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[2] Custom Akamai HTTP/2 Fingerprint")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest",
		sensor.WithCustomFingerprint(sensor.CustomFingerprint{
			Akamai: chromeAkamai,
		}),
	)
	defer session.Close()

	resp, err := session.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		HTTP2 struct {
			AkamaiFingerprint string `json:"akamai_fingerprint"`
		} `json:"http2"`
	}
	json.Unmarshal(body, &result)

	fmt.Printf("Akamai fingerprint: %s\n", result.HTTP2.AkamaiFingerprint)
	fmt.Printf("Expected:           %s\n", chromeAkamai)
	fmt.Printf("Match: %v\n", result.HTTP2.AkamaiFingerprint == chromeAkamai)
}

func example3Combined(ctx context.Context) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[3] Combined JA3 + Akamai")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest",
		sensor.WithCustomFingerprint(sensor.CustomFingerprint{
			JA3:    chrome131JA3,
			Akamai: chromeAkamai,
		}),
	)
	defer session.Close()

	resp, err := session.Get(ctx, "https://tls.peet.ws/api/all")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		TLS struct {
			JA3Hash string `json:"ja3_hash"`
		} `json:"tls"`
		HTTP2 struct {
			AkamaiFingerprint string `json:"akamai_fingerprint"`
		} `json:"http2"`
	}
	json.Unmarshal(body, &result)

	fmt.Printf("JA3 hash:    %s\n", result.TLS.JA3Hash)
	fmt.Printf("Akamai:      %s\n", result.HTTP2.AkamaiFingerprint)
	fmt.Println("\nBoth TLS and HTTP/2 fingerprints are fully custom.")
}

func example4ExtraOptions(ctx context.Context) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("[4] Extra Fingerprint Options")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest",
		sensor.WithCustomFingerprint(sensor.CustomFingerprint{
			JA3:               chrome131JA3,
			ALPN:              []string{"h2", "http/1.1"},
			CertCompression:   []string{"brotli"},
			PermuteExtensions: true,
		}),
	)
	defer session.Close()

	resp, err := session.Get(ctx, "https://tls.peet.ws/api/tls")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result struct {
		TLS struct {
			JA3Hash string `json:"ja3_hash"`
		} `json:"tls"`
	}
	json.Unmarshal(body, &result)

	fmt.Printf("JA3 hash: %s\n", result.TLS.JA3Hash)
	fmt.Println("Extensions are randomly permuted — JA3 hash will vary each run")
	fmt.Println("but cipher suites and curves remain the same.")
}

func printSummary() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Summary: Custom Fingerprinting Options")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println(`
JA3 fingerprint (CustomFingerprint.JA3):
  - Overrides the TLS ClientHello fingerprint
  - Format: TLSVersion,Ciphers,Extensions,Curves,PointFormats
  - Automatically enables TLS-only mode (no preset HTTP headers)

Akamai fingerprint (CustomFingerprint.Akamai):
  - Overrides HTTP/2 SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order
  - Format: SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER
  - Works alongside the preset's TLS fingerprint

Extra options (CustomFingerprint fields):
  - ALPN: []string{"h2", "http/1.1"}
  - SignatureAlgorithms: []string{"ecdsa_secp256r1_sha256", ...}
  - CertCompression: []string{"brotli", "zlib", "zstd"}
  - PermuteExtensions: true/false
`)
}
