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

## Other languages

Native bindings live in `bindings/` for Node, Python, .NET. Build the shared lib with the workflow in `.github/workflows/bindings.yml` or by hand:

```
cd bindings/clib && CGO_ENABLED=1 go build -buildmode=c-shared -o libsensor.so .
```

## Support

If this saves you time, throw some sats:

`bc1qt5wfzw6586s6vg24fzk05qsuzj8vk5xxt7wl36`
