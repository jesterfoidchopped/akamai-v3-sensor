package proxy

import (
	"net/url"
	"strings"
)

var knownMASQUEProviders = []string{
	"brd.superproxy.io",
	"zproxy.lum-superproxy.io",
	"lum-superproxy.io",
	"pr.oxylabs.io",
	"residential-eu.oxylabs.io",
	"gate.smartproxy.com",
	"proxy.soax.com",
}

func IsMASQUEProvider(host string) bool {
	host = strings.ToLower(host)
	for _, provider := range knownMASQUEProviders {
		if strings.Contains(host, provider) || strings.HasSuffix(host, provider) {
			return true
		}
	}
	return false
}

func IsMASQUEProxyURL(proxyURL string) bool {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return false
	}

	if parsed.Scheme == "masque" {
		return true
	}

	if parsed.Scheme == "https" && IsMASQUEProvider(parsed.Host) {
		return true
	}

	return false
}

func NormalizeMASQUEURL(proxyURL string) (string, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return "", err
	}

	if parsed.Scheme == "masque" {
		parsed.Scheme = "https"
	}

	return parsed.String(), nil
}

func AddMASQUEProvider(hostname string) {
	hostname = strings.ToLower(hostname)
	for _, p := range knownMASQUEProviders {
		if p == hostname {
			return
		}
	}
	knownMASQUEProviders = append(knownMASQUEProviders, hostname)
}
