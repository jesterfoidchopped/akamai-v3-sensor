# akamai-v3-sensor

Go HTTP client with browser-grade TLS, HTTP/2 and HTTP/3 fingerprinting. Use it to make requests that look like a real Chrome / Firefox / Safari, without the bot-detection headaches.

## Install

```
go get github.com/jesterfoidchopped/akamai-v3-sensor
```

## Basic use

```go
package main

import (
	"context"
	"fmt"

	sensor "github.com/jesterfoidchopped/akamai-v3-sensor"
)

func main() {
	c := sensor.New("chrome-146")
	defer c.Close()

	resp, err := c.Get(context.Background(), "https://tls.peet.ws/api/all")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(resp.Body))
}
```

## With options

```go
c := sensor.New("chrome-146",
	sensor.WithTimeout(30*time.Second),
	sensor.WithProxy("http://user:pass@host:port"),
)
```

Supported preset names live in `fingerprint/` (`chrome-146`, `firefox-132`, `safari-18`, etc).

## Request-based Akamai bypass

This is a pure HTTP client. No headless browser, no JS VM, no `sensor_data` generator. For most Akamai-fronted sites the TLS + HTTP/2 fingerprint alone is enough to land a valid `_abck` cookie (the `~0~` segment is the trusted marker, `~-1~` means you failed scoring).

Quick way to verify the client is shaped right:

```go
c := sensor.New("chrome-146")
defer c.Close()

resp, _ := c.Get(context.Background(), "https://tls.peet.ws/api/all")
// JA3, JA4, akamai_fingerprint should match a real Chrome 146.
```

Then point it at an actual Akamai target and inspect the cookie jar:

```go
resp, _ := c.Get(context.Background(), "https://www.nike.com/")
fmt.Println(resp.GetHeaders("set-cookie")) // look for _abck=...~0~... and bm_sz=...
```

Other endpoints people use as Akamai test targets: `www.adidas.com`, `www.footlocker.com`, `www.target.com`, `www.lululemon.com`, `www.bestbuy.com`, `www.ticketmaster.com`. If `_abck` comes back with `~0~` on the first or second request, phase-one scoring passed and you do not need to forge a sensor_data payload for that origin.

## Other languages

Native bindings live in `bindings/` for Node, Python, .NET. Build the shared lib with the workflow in `.github/workflows/bindings.yml` or by hand:

```
cd bindings/clib && CGO_ENABLED=1 go build -buildmode=c-shared -o libsensor.so .
```

## Support

If this saves you time, throw some sats:

`bc1qt5wfzw6586s6vg24fzk05qsuzj8vk5xxt7wl36`
