package client

import (
	"fmt"
	"os"
)

func HeadersFromMap(old map[string]string) map[string][]string {
	fmt.Fprintln(os.Stderr, "sensor: DEPRECATION WARNING - map[string]string headers are deprecated.")
	fmt.Fprintln(os.Stderr, "           Please use map[string][]string instead.")
	fmt.Fprintln(os.Stderr, "           Example: map[string][]string{\"Content-Type\": {\"application/json\"}}")

	if old == nil {
		return nil
	}

	headers := make(map[string][]string, len(old))
	for k, v := range old {
		headers[k] = []string{v}
	}
	return headers
}

type H map[string]string

func (h H) ToMulti() map[string][]string {
	if h == nil {
		return nil
	}
	result := make(map[string][]string, len(h))
	for k, v := range h {
		result[k] = []string{v}
	}
	return result
}

func MakeHeaders(keyValuePairs ...string) map[string][]string {
	if len(keyValuePairs)%2 != 0 {
		panic("MakeHeaders: odd number of arguments, expected key-value pairs")
	}

	headers := make(map[string][]string, len(keyValuePairs)/2)
	for i := 0; i < len(keyValuePairs); i += 2 {
		key := keyValuePairs[i]
		value := keyValuePairs[i+1]
		headers[key] = append(headers[key], value)
	}
	return headers
}
