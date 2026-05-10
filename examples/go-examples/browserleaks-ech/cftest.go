package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/client"
)

func main() {
	ctx := context.Background()

	c := client.NewClient("chrome-latest-windows",
		client.WithTimeout(30*time.Second),
	)
	defer c.Close()

	resp, _ := c.Do(ctx, &client.Request{
		Method:        "GET",
		URL:           "https://quic.browserleaks.com/?minify=1",
		ForceProtocol: client.ProtocolHTTP3,
	})
	text, _ := resp.Text()
	fmt.Println(text)
}
