package fingerprint

import (
	"fmt"
	"net/url"
	"strings"
)

type FetchMode string

const (
	FetchModeNavigate   FetchMode = "navigate"
	FetchModeCORS       FetchMode = "cors"
	FetchModeNoCORS     FetchMode = "no-cors"
	FetchModeSameOrigin FetchMode = "same-origin"
	FetchModeWebSocket  FetchMode = "websocket"
)

type FetchDest string

const (
	FetchDestDocument      FetchDest = "document"
	FetchDestEmbed         FetchDest = "embed"
	FetchDestFont          FetchDest = "font"
	FetchDestImage         FetchDest = "image"
	FetchDestManifest      FetchDest = "manifest"
	FetchDestMedia         FetchDest = "media"
	FetchDestObject        FetchDest = "object"
	FetchDestReport        FetchDest = "report"
	FetchDestScript        FetchDest = "script"
	FetchDestServiceWorker FetchDest = "serviceworker"
	FetchDestSharedWorker  FetchDest = "sharedworker"
	FetchDestStyle         FetchDest = "style"
	FetchDestWorker        FetchDest = "worker"
	FetchDestXHR           FetchDest = "empty" // XHR/fetch uses "empty"
)

type FetchSite string

const (
	FetchSiteNone       FetchSite = "none"        // Direct navigation (typing URL)
	FetchSiteSameOrigin FetchSite = "same-origin" // Same origin request
	FetchSiteSameSite   FetchSite = "same-site"   // Same site but different subdomain
	FetchSiteCrossSite  FetchSite = "cross-site"  // Different site entirely
)

type RequestContext struct {
	Mode            FetchMode
	Dest            FetchDest
	Site            FetchSite
	IsUserTriggered bool
	Referrer        string
	TargetURL       string
}

func NavigationContext() RequestContext {
	return RequestContext{
		Mode:            FetchModeNavigate,
		Dest:            FetchDestDocument,
		Site:            FetchSiteNone,
		IsUserTriggered: true,
	}
}

func XHRContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeCORS,
		Dest:            FetchDestXHR,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

func ImageContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeNoCORS,
		Dest:            FetchDestImage,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

func ScriptContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeNoCORS,
		Dest:            FetchDestScript,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

func StyleContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeNoCORS,
		Dest:            FetchDestStyle,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

func FontContext(referrer, targetURL string) RequestContext {
	site := calculateFetchSite(referrer, targetURL)
	return RequestContext{
		Mode:            FetchModeCORS,
		Dest:            FetchDestFont,
		Site:            site,
		IsUserTriggered: false,
		Referrer:        referrer,
		TargetURL:       targetURL,
	}
}

func calculateFetchSite(referrer, targetURL string) FetchSite {
	if referrer == "" {
		return FetchSiteNone
	}

	refURL, err := url.Parse(referrer)
	if err != nil {
		return FetchSiteCrossSite
	}

	targURL, err := url.Parse(targetURL)
	if err != nil {
		return FetchSiteCrossSite
	}

	if refURL.Scheme == targURL.Scheme && refURL.Host == targURL.Host {
		return FetchSiteSameOrigin
	}

	refDomain := getRegistrableDomain(refURL.Host)
	targDomain := getRegistrableDomain(targURL.Host)
	if refDomain == targDomain && refURL.Scheme == targURL.Scheme {
		return FetchSiteSameSite
	}

	return FetchSiteCrossSite
}

func getRegistrableDomain(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

type SecFetchHeaders struct {
	Site string
	Mode string
	Dest string
	User string // "?1" for user-triggered, empty otherwise
}

func GenerateSecFetchHeaders(ctx RequestContext) SecFetchHeaders {
	headers := SecFetchHeaders{
		Site: string(ctx.Site),
		Mode: string(ctx.Mode),
		Dest: string(ctx.Dest),
	}

	if ctx.IsUserTriggered && ctx.Mode == FetchModeNavigate {
		headers.User = "?1"
	}

	return headers
}

type ClientHints struct {
	UA         string // Sec-Ch-Ua
	UAMobile   string // Sec-Ch-Ua-Mobile
	UAPlatform string // Sec-Ch-Ua-Platform

	UAArch            string // Sec-Ch-Ua-Arch
	UABitness         string // Sec-Ch-Ua-Bitness
	UAFullVersionList string // Sec-Ch-Ua-Full-Version-List
	UAModel           string // Sec-Ch-Ua-Model
	UAPlatformVersion string // Sec-Ch-Ua-Platform-Version
}

func GenerateClientHints(chromeVersion string, platform PlatformInfo, includeHighEntropy bool) ClientHints {
	hints := ClientHints{
		UA:         fmt.Sprintf(`"Google Chrome";v="%s", "Chromium";v="%s", "Not_A Brand";v="24"`, chromeVersion, chromeVersion),
		UAMobile:   "?0",
		UAPlatform: fmt.Sprintf(`"%s"`, platform.Platform),
	}

	if includeHighEntropy {
		hints.UAArch = fmt.Sprintf(`"%s"`, platform.Arch)
		hints.UABitness = `"64"`
		hints.UAFullVersionList = fmt.Sprintf(`"Google Chrome";v="%s.0.0.0", "Chromium";v="%s.0.0.0", "Not_A Brand";v="24.0.0.0"`, chromeVersion, chromeVersion)
		hints.UAPlatformVersion = fmt.Sprintf(`"%s"`, platform.PlatformVersion)
	}

	return hints
}

type HeaderCoherence struct {
	preset   *Preset
	platform PlatformInfo
}

func NewHeaderCoherence(preset *Preset) *HeaderCoherence {
	return &HeaderCoherence{
		preset:   preset,
		platform: GetPlatformInfo(),
	}
}

func (h *HeaderCoherence) ApplyToHeaders(headers map[string]string, ctx RequestContext) {
	secFetch := GenerateSecFetchHeaders(ctx)
	headers["Sec-Fetch-Site"] = secFetch.Site
	headers["Sec-Fetch-Mode"] = secFetch.Mode
	headers["Sec-Fetch-Dest"] = secFetch.Dest
	if secFetch.User != "" {
		headers["Sec-Fetch-User"] = secFetch.User
	} else {
		delete(headers, "Sec-Fetch-User")
	}

	switch ctx.Mode {
	case FetchModeNavigate:
		headers["Upgrade-Insecure-Requests"] = "1"
		headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	case FetchModeCORS, FetchModeSameOrigin:
		headers["Accept"] = "*/*"
		delete(headers, "Upgrade-Insecure-Requests")
		delete(headers, "Cache-Control")
	case FetchModeNoCORS:
		switch ctx.Dest {
		case FetchDestImage:
			headers["Accept"] = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
		case FetchDestStyle:
			headers["Accept"] = "text/css,*/*;q=0.1"
		case FetchDestScript:
			headers["Accept"] = "*/*"
		default:
			headers["Accept"] = "*/*"
		}
		delete(headers, "Upgrade-Insecure-Requests")
		delete(headers, "Cache-Control")
	}

	if ctx.Referrer != "" {
		headers["Referer"] = ctx.Referrer
	}
}

func (h *HeaderCoherence) GenerateNavigationHeaders() map[string]string {
	headers := make(map[string]string)

	for k, v := range h.preset.Headers {
		headers[k] = v
	}

	h.ApplyToHeaders(headers, NavigationContext())

	return headers
}

func (h *HeaderCoherence) GenerateXHRHeaders(referrer, targetURL string) map[string]string {
	headers := make(map[string]string)

	headers["User-Agent"] = h.preset.UserAgent
	headers["Accept"] = "*/*"
	headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
	headers["Accept-Language"] = "en-US,en;q=0.9"

	if ua, ok := h.preset.Headers["sec-ch-ua"]; ok {
		headers["sec-ch-ua"] = ua
	}
	if uaMobile, ok := h.preset.Headers["sec-ch-ua-mobile"]; ok {
		headers["sec-ch-ua-mobile"] = uaMobile
	}
	if uaPlatform, ok := h.preset.Headers["sec-ch-ua-platform"]; ok {
		headers["sec-ch-ua-platform"] = uaPlatform
	}

	h.ApplyToHeaders(headers, XHRContext(referrer, targetURL))

	return headers
}
