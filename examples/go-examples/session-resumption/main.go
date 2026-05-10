package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor"
)

const sessionFile = "session_state.json"

type CFResponse struct {
	BotManagement struct {
		Score int `json:"score"`
	} `json:"botManagement"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Session Resumption Examples")
	fmt.Println(strings.Repeat("=", 60))

	example1SaveLoad(ctx)
	example2MarshalUnmarshal(ctx)
	example3CrossDomainWarming(ctx)
	example4ProductionPattern(ctx)

	os.Remove(sessionFile)
	os.Remove("my_scraper.json")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Session resumption examples completed!")
	fmt.Println(strings.Repeat("=", 60))
}

func example1SaveLoad(ctx context.Context) {
	fmt.Println("\n[1] Save and Load Session (File)")
	fmt.Println(strings.Repeat("-", 50))

	var session *sensor.Session

	if _, err := os.Stat(sessionFile); err == nil {
		fmt.Println("Loading existing session...")
		session, err = sensor.LoadSession(sessionFile)
		if err != nil {
			fmt.Printf("Failed to load: %v, creating new\n", err)
			session = sensor.NewSession("chrome-latest")
		} else {
			fmt.Println("Session loaded with TLS tickets!")
		}
	} else {
		fmt.Println("Creating new session...")
		session = sensor.NewSession("chrome-latest")

		fmt.Println("Warming up session...")
		resp, _ := session.Get(ctx, "https://cloudflare.com/cdn-cgi/trace")
		if resp != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			fmt.Printf("Warmup complete - Protocol: %s\n", resp.Protocol)
		}
	}
	defer session.Close()

	resp, _ := session.Get(ctx, "https://www.cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Request - Protocol: %s\n", resp.Protocol)
	}

	if err := session.Save(sessionFile); err != nil {
		fmt.Printf("Failed to save: %v\n", err)
	} else {
		fmt.Printf("Session saved to %s\n", sessionFile)
	}
}

func example2MarshalUnmarshal(ctx context.Context) {
	fmt.Println("\n[2] Marshal/Unmarshal Session (Bytes)")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest")
	resp, _ := session.Get(ctx, "https://cloudflare.com/")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	sessionData, err := session.Marshal()
	if err != nil {
		fmt.Printf("Marshal failed: %v\n", err)
		session.Close()
		return
	}
	fmt.Printf("Marshaled session: %d bytes\n", len(sessionData))
	session.Close()

	restored, err := sensor.UnmarshalSession(sessionData)
	if err != nil {
		fmt.Printf("Unmarshal failed: %v\n", err)
		return
	}
	defer restored.Close()

	resp, _ = restored.Get(ctx, "https://www.cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Restored session request - Protocol: %s\n", resp.Protocol)
	}
}

func example3CrossDomainWarming(ctx context.Context) {
	fmt.Println("\n[3] Cross-Domain Warming")
	fmt.Println(strings.Repeat("-", 50))

	session := sensor.NewSession("chrome-latest")
	defer session.Close()

	fmt.Println("Warming up on cloudflare.com...")
	resp, _ := session.Get(ctx, "https://cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		fmt.Printf("Warmup - Protocol: %s\n", resp.Protocol)
	}

	fmt.Println("\nUsing warmed session on cf.erisa.uk (CF-protected)...")
	resp, _ = session.Get(ctx, "https://cf.erisa.uk/")
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cf CFResponse
		json.Unmarshal(body, &cf)
		fmt.Printf("Bot Score: %d\n", cf.BotManagement.Score)
		fmt.Printf("Protocol: %s\n", resp.Protocol)
	}
}

func example4ProductionPattern(ctx context.Context) {
	fmt.Println("\n[4] Production Pattern")
	fmt.Println(strings.Repeat("-", 50))

	session := getOrCreateSession(ctx, "my_scraper")
	defer session.Close()

	resp, _ := session.Get(ctx, "https://cf.erisa.uk/")
	if resp != nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cf CFResponse
		json.Unmarshal(body, &cf)
		fmt.Printf("Bot Score: %d\n", cf.BotManagement.Score)
	}
}

func getOrCreateSession(ctx context.Context, sessionKey string) *sensor.Session {
	sessionPath := sessionKey + ".json"

	if _, err := os.Stat(sessionPath); err == nil {
		session, err := sensor.LoadSession(sessionPath)
		if err == nil {
			return session
		}
	}

	session := sensor.NewSession("chrome-latest")

	resp, _ := session.Get(ctx, "https://cloudflare.com/cdn-cgi/trace")
	if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	session.Save(sessionPath)

	return session
}
