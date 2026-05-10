package fingerprint

import (
	"runtime"

	tls "github.com/sardanioss/utls"
)

type PlatformInfo struct {
	UserAgentOS        string // e.g., "(Windows NT 10.0; Win64; x64)" or "(X11; Linux x86_64)"
	Platform           string // e.g., "Windows", "Linux", "macOS"
	Arch               string // e.g., "x86", "arm"
	PlatformVersion    string // e.g., "10.0.0", "6.12.0", "14.7.0"
	FirefoxUserAgentOS string // Firefox has slightly different format
}

func GetPlatformInfo() PlatformInfo {
	switch runtime.GOOS {
	case "windows":
		return PlatformInfo{
			UserAgentOS:        "(Windows NT 10.0; Win64; x64)",
			Platform:           "Windows",
			Arch:               "x86",
			PlatformVersion:    "10.0.0",
			FirefoxUserAgentOS: "(Windows NT 10.0; Win64; x64; rv:133.0)",
		}
	case "darwin":
		return PlatformInfo{
			UserAgentOS:        "(Macintosh; Intel Mac OS X 10_15_7)",
			Platform:           "macOS",
			Arch:               "arm",
			PlatformVersion:    "14.7.0",
			FirefoxUserAgentOS: "(Macintosh; Intel Mac OS X 10.15; rv:133.0)",
		}
	default: // linux and others
		return PlatformInfo{
			UserAgentOS:        "(X11; Linux x86_64)",
			Platform:           "Linux",
			Arch:               "x86",
			PlatformVersion:    "6.12.0",
			FirefoxUserAgentOS: "(X11; Linux x86_64; rv:133.0)",
		}
	}
}

type HeaderPair struct {
	Key   string
	Value string
}

type Preset struct {
	Name                 string
	ClientHelloID        tls.ClientHelloID // For TCP/TLS (HTTP/1.1, HTTP/2)
	PSKClientHelloID     tls.ClientHelloID // For TCP/TLS with PSK (session resumption)
	QUICClientHelloID    tls.ClientHelloID // For QUIC/HTTP/3 (different TLS extensions)
	QUICPSKClientHelloID tls.ClientHelloID // For QUIC/HTTP/3 with PSK (session resumption)
	UserAgent            string
	Headers              map[string]string // For backward compatibility
	HeaderOrder          []HeaderPair      // Ordered headers for HTTP/2
	HTTP2Settings        HTTP2Settings
	TCPFingerprint       TCPFingerprint
	SupportHTTP3         bool
	H2Config             *H2FingerprintConfig // nil = Chrome defaults for all H2 fingerprinting
	H3Config             *H3FingerprintConfig // nil = Chrome defaults for all H3/QUIC fingerprinting
	JA3                  string               // JA3 fingerprint string. When set, parsed fresh per connection instead of using ClientHelloID.
	JA3Extras            *JA3Extras           // Supplements JA3 parsing. nil = Chrome defaults.
	BasedOn              string               // For custom presets: name of the parent preset (used by inheritance-loop detection). Empty for built-ins.
}

type TCPFingerprint struct {
	TTL         int  // IP Time-To-Live: 128=Windows, 64=Linux/macOS/iOS/Android
	MSS         int  // TCP Maximum Segment Size: 1460 for standard Ethernet
	WindowSize  int  // TCP Window Size in SYN: 64240=Win10/11, 65535=Linux/macOS
	WindowScale int  // TCP Window Scale option: 8=Win10/11, 7=Linux/Android, 6=macOS/iOS
	DFBit       bool // IP Don't Fragment flag
}

func WindowsTCPFingerprint() TCPFingerprint {
	return TCPFingerprint{TTL: 128, MSS: 1460, WindowSize: 64240, WindowScale: 8, DFBit: true}
}

func LinuxTCPFingerprint() TCPFingerprint {
	return TCPFingerprint{TTL: 64, MSS: 1460, WindowSize: 65535, WindowScale: 7, DFBit: true}
}

func MacOSTCPFingerprint() TCPFingerprint {
	return TCPFingerprint{TTL: 64, MSS: 1460, WindowSize: 65535, WindowScale: 6, DFBit: true}
}

func PlatformTCPFingerprint(platform string) TCPFingerprint {
	switch platform {
	case "Windows":
		return WindowsTCPFingerprint()
	case "macOS":
		return MacOSTCPFingerprint()
	default:
		return LinuxTCPFingerprint()
	}
}

type HTTP2Settings struct {
	HeaderTableSize        uint32
	EnablePush             bool
	MaxConcurrentStreams   uint32
	InitialWindowSize      uint32
	MaxFrameSize           uint32
	MaxHeaderListSize      uint32
	ConnectionWindowUpdate uint32
	StreamWeight           uint16 // Chrome sends 255 on wire (set to 256, code does -1)
	StreamExclusive        bool
	NoRFC7540Priorities    bool
}

type H2FingerprintConfig struct {
	HPACKHeaderOrder    []string // HPACK wire encoding order. nil = Chrome 143 default.
	HPACKIndexingPolicy string   // "chrome"/"never"/"always"/"default". "" = "chrome".
	HPACKNeverIndex     []string // Headers never HPACK-indexed. nil = Chrome default.
	StreamPriorityMode  string   // "chrome"/"default". "" = "chrome".
	DisableCookieSplit  *bool    // nil = true (Chrome sends single cookie entry).
	SettingsOrder       []uint16 // H2 SETTINGS frame ID order. nil = dynamic from HTTP2Settings.
	PseudoHeaderOrder   []string // Pseudo-header order. nil = heuristic (Chrome m,a,s,p / Safari m,s,p,a).

	PriorityTable map[string]ResourcePriority
}

type ResourcePriority struct {
	Urgency     uint8 // 0–7; 3 = default (no `u=` on header)
	Incremental bool  // RFC 9218 `i` parameter
	EmitHeader  bool  // false → suppress the priority: HTTP header entirely
}

const chromePriorityDefaultUrgency uint8 = 3

var defaultPriorityTable = map[string]ResourcePriority{
	"audio":    {Urgency: 3, Incremental: true, EmitHeader: true},
	"document": {Urgency: 0, Incremental: true, EmitHeader: true},
	"embed":    {Urgency: 0, Incremental: true, EmitHeader: true},
	"empty":    {Urgency: 1, Incremental: true, EmitHeader: true},
	"font":     {Urgency: 1, Incremental: false, EmitHeader: true},
	"iframe":   {Urgency: 0, Incremental: true, EmitHeader: true},
	"image":    {Urgency: 2, Incremental: true, EmitHeader: true},
	"manifest": {Urgency: 2, Incremental: false, EmitHeader: true},
	"object":   {Urgency: 0, Incremental: true, EmitHeader: true},
	"script":   {Urgency: 1, Incremental: false, EmitHeader: true},
	"style":    {Urgency: 0, Incremental: false, EmitHeader: true},
	"track":    {Urgency: 3, Incremental: true, EmitHeader: true},
	"video":    {Urgency: 3, Incremental: true, EmitHeader: true},
	"worker":   {Urgency: 4, Incremental: true, EmitHeader: true},
}

func DefaultPriorityTable() map[string]ResourcePriority {
	out := make(map[string]ResourcePriority, len(defaultPriorityTable))
	for k, v := range defaultPriorityTable {
		out[k] = v
	}
	return out
}

func PriorityFromUrgency(urgency uint8) uint16 {
	if urgency > 7 {
		urgency = 7
	}
	return uint16(256 - (uint32(urgency)*73)/2)
}

func PriorityHeaderFromResource(rp ResourcePriority) string {
	if !rp.EmitHeader {
		return ""
	}
	uIsDefault := rp.Urgency == chromePriorityDefaultUrgency
	switch {
	case uIsDefault && !rp.Incremental:
		return ""
	case uIsDefault && rp.Incremental:
		return "i"
	case !uIsDefault && !rp.Incremental:
		return "u=" + uint8ToASCII(rp.Urgency)
	default: // !uIsDefault && rp.Incremental
		return "u=" + uint8ToASCII(rp.Urgency) + ", i"
	}
}

func uint8ToASCII(v uint8) string {
	if v <= 9 {
		return string([]byte{'0' + v})
	}
	return string([]byte{'0' + v/10, '0' + v%10})
}

type H3FingerprintConfig struct {
	QPACKMaxTableCapacity     *uint64 // nil = 65536 (Chrome). Safari heuristic fallback.
	QPACKBlockedStreams       *uint64 // nil = 100
	MaxFieldSectionSize       *uint64 // nil = 262144 (Chrome). 0 to omit (Safari).
	EnableDatagrams           *bool   // nil = true (Chrome). Safari heuristic fallback.
	QUICInitialPacketSize     *uint16 // nil = 1250 (Chrome). MASQUE overrides to 1350.
	QUICMaxIncomingStreams    *int64  // nil = 100
	QUICMaxIncomingUniStreams *int64  // nil = 103
	QUICAllow0RTT             *bool   // nil = true
	QUICChromeStyleInitial    *bool   // nil = true
	QUICDisableHelloScramble  *bool   // nil = true
	QUICTransportParamOrder   string  // "chrome"/"random". "" = "chrome".
	QUICConnectionIDLength    *int    // nil = 0 (Chrome empty SCID). Firefox uses 8.
	QUICMaxDatagramFrameSize  *uint64 // nil = 65536 (Chrome). 0 to use quic-go default (16383).
	MaxResponseHeaderBytes    *uint64 // nil = 262144
	SendGreaseFrames          *bool   // nil = true

	QUICInitialStreamReceiveWindow     *uint64 // nil = quic-go default. iOS Chrome sends 2097152.
	QUICInitialConnectionReceiveWindow *uint64 // nil = quic-go default. iOS Chrome sends 16777216.
}

func (p *Preset) H2HeaderOrder() []string {
	if p.H2Config != nil && p.H2Config.HPACKHeaderOrder != nil {
		return p.H2Config.HPACKHeaderOrder
	}
	return []string{
		"cache-control",
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent",
		"content-type", "content-length",
		"accept", "origin",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"referer",
		"accept-encoding", "accept-language",
		"cookie", "priority",
	}
}

func (p *Preset) H2HPACKIndexingPolicy() string {
	if p.H2Config != nil && p.H2Config.HPACKIndexingPolicy != "" {
		return p.H2Config.HPACKIndexingPolicy
	}
	return "chrome"
}

func (p *Preset) H2HPACKNeverIndex() []string {
	if p.H2Config != nil && p.H2Config.HPACKNeverIndex != nil {
		return p.H2Config.HPACKNeverIndex
	}
	return []string{"cookie", "authorization", "proxy-authorization"}
}

func (p *Preset) H2StreamPriorityMode() string {
	if p.H2Config != nil && p.H2Config.StreamPriorityMode != "" {
		return p.H2Config.StreamPriorityMode
	}
	return "chrome"
}

func (p *Preset) H2DisableCookieSplit() bool {
	if p.H2Config != nil && p.H2Config.DisableCookieSplit != nil {
		return *p.H2Config.DisableCookieSplit
	}
	return true // Chrome default
}

func (p *Preset) H2SettingsOrder() []uint16 {
	if p.H2Config != nil && p.H2Config.SettingsOrder != nil {
		return p.H2Config.SettingsOrder
	}
	return nil
}

func (p *Preset) H2PseudoHeaderOrder() []string {
	if p.H2Config != nil && p.H2Config.PseudoHeaderOrder != nil {
		return p.H2Config.PseudoHeaderOrder
	}
	return nil
}

func (p *Preset) H2HasPriorityTable() bool {
	if p.H2Config != nil && len(p.H2Config.PriorityTable) > 0 {
		return true
	}
	if p.HTTP2Settings.NoRFC7540Priorities {
		return false
	}
	return len(defaultPriorityTable) > 0
}

func (p *Preset) H2PriorityFor(dest string) (weight uint16, exclusive bool, headerValue string, ok bool) {
	var table map[string]ResourcePriority
	switch {
	case p.H2Config != nil && len(p.H2Config.PriorityTable) > 0:
		table = p.H2Config.PriorityTable
	case p.HTTP2Settings.NoRFC7540Priorities:
		return 0, false, "", false
	default:
		table = defaultPriorityTable
	}
	rp, found := table[dest]
	if !found {
		return 0, false, "", false
	}
	return PriorityFromUrgency(rp.Urgency), true, PriorityHeaderFromResource(rp), true
}

func (p *Preset) H3QPACKMaxTableCapacity() uint64 {
	if p.H3Config != nil && p.H3Config.QPACKMaxTableCapacity != nil {
		return *p.H3Config.QPACKMaxTableCapacity
	}
	if p.HTTP2Settings.NoRFC7540Priorities {
		return 16383
	}
	return 65536 // Chrome default
}

func (p *Preset) H3QPACKBlockedStreams() uint64 {
	if p.H3Config != nil && p.H3Config.QPACKBlockedStreams != nil {
		return *p.H3Config.QPACKBlockedStreams
	}
	return 100
}

func (p *Preset) H3MaxFieldSectionSize() uint64 {
	if p.H3Config != nil && p.H3Config.MaxFieldSectionSize != nil {
		return *p.H3Config.MaxFieldSectionSize
	}
	if p.HTTP2Settings.NoRFC7540Priorities {
		return 0
	}
	return 262144 // Chrome default
}

func (p *Preset) H3EnableDatagrams() bool {
	if p.H3Config != nil && p.H3Config.EnableDatagrams != nil {
		return *p.H3Config.EnableDatagrams
	}
	if p.HTTP2Settings.NoRFC7540Priorities {
		return false
	}
	return true // Chrome default
}

func (p *Preset) H3QUICInitialPacketSize() uint16 {
	if p.H3Config != nil && p.H3Config.QUICInitialPacketSize != nil {
		return *p.H3Config.QUICInitialPacketSize
	}
	return 1250 // Chrome default
}

func (p *Preset) H3QUICMaxIncomingStreams() int64 {
	if p.H3Config != nil && p.H3Config.QUICMaxIncomingStreams != nil {
		return *p.H3Config.QUICMaxIncomingStreams
	}
	return 100
}

func (p *Preset) H3QUICMaxIncomingUniStreams() int64 {
	if p.H3Config != nil && p.H3Config.QUICMaxIncomingUniStreams != nil {
		return *p.H3Config.QUICMaxIncomingUniStreams
	}
	return 103
}

func (p *Preset) H3QUICAllow0RTT() bool {
	if p.H3Config != nil && p.H3Config.QUICAllow0RTT != nil {
		return *p.H3Config.QUICAllow0RTT
	}
	return true
}

func (p *Preset) H3QUICChromeStyleInitial() bool {
	if p.H3Config != nil && p.H3Config.QUICChromeStyleInitial != nil {
		return *p.H3Config.QUICChromeStyleInitial
	}
	return true
}

func (p *Preset) H3QUICDisableHelloScramble() bool {
	if p.H3Config != nil && p.H3Config.QUICDisableHelloScramble != nil {
		return *p.H3Config.QUICDisableHelloScramble
	}
	return true
}

func (p *Preset) H3QUICTransportParamOrder() string {
	if p.H3Config != nil && p.H3Config.QUICTransportParamOrder != "" {
		return p.H3Config.QUICTransportParamOrder
	}
	return "chrome"
}

func (p *Preset) H3QUICConnectionIDLength() int {
	if p.H3Config != nil && p.H3Config.QUICConnectionIDLength != nil {
		return *p.H3Config.QUICConnectionIDLength
	}
	return 0 // Chrome default: empty SCID
}

func (p *Preset) H3QUICMaxDatagramFrameSize() uint64 {
	if p.H3Config != nil && p.H3Config.QUICMaxDatagramFrameSize != nil {
		return *p.H3Config.QUICMaxDatagramFrameSize
	}
	return 65536 // Chrome default
}

func (p *Preset) H3MaxResponseHeaderBytes() uint64 {
	if p.H3Config != nil && p.H3Config.MaxResponseHeaderBytes != nil {
		return *p.H3Config.MaxResponseHeaderBytes
	}
	return 262144
}

func (p *Preset) H3SendGreaseFrames() bool {
	if p.H3Config != nil && p.H3Config.SendGreaseFrames != nil {
		return *p.H3Config.SendGreaseFrames
	}
	return true
}

func (p *Preset) H3QUICInitialStreamReceiveWindow() uint64 {
	if p.H3Config != nil && p.H3Config.QUICInitialStreamReceiveWindow != nil {
		return *p.H3Config.QUICInitialStreamReceiveWindow
	}
	return 0
}

func (p *Preset) H3QUICInitialConnectionReceiveWindow() uint64 {
	if p.H3Config != nil && p.H3Config.QUICInitialConnectionReceiveWindow != nil {
		return *p.H3Config.QUICInitialConnectionReceiveWindow
	}
	return 0
}

func chromeH2Config() *H2FingerprintConfig {
	t := true
	return &H2FingerprintConfig{
		HPACKHeaderOrder: []string{
			"cache-control",
			"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
			"upgrade-insecure-requests", "user-agent",
			"content-type", "content-length",
			"accept", "origin",
			"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
			"referer",
			"accept-encoding", "accept-language",
			"cookie", "priority",
		},
		HPACKIndexingPolicy: "chrome",
		StreamPriorityMode:  "chrome",
		DisableCookieSplit:  &t,
		SettingsOrder:       []uint16{1, 2, 4, 6},
		PseudoHeaderOrder:   []string{":method", ":authority", ":scheme", ":path"},
	}
}

func firefoxH2Config() *H2FingerprintConfig {
	f := false
	return &H2FingerprintConfig{
		HPACKHeaderOrder: []string{
			"user-agent",
			"accept", "accept-language", "accept-encoding",
			"upgrade-insecure-requests",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"priority", "te",
			"referer", "cookie",
			"content-type", "content-length", "origin",
		},
		HPACKIndexingPolicy: "default",
		StreamPriorityMode:  "default",
		DisableCookieSplit:  &f,
		SettingsOrder:       []uint16{1, 2, 4, 5},
		PseudoHeaderOrder:   []string{":method", ":path", ":authority", ":scheme"},
	}
}

func safariH2Config() *H2FingerprintConfig {
	t := true
	return &H2FingerprintConfig{
		HPACKHeaderOrder: []string{
			"accept",
			"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
			"accept-language", "accept-encoding",
			"user-agent", "referer", "cookie",
			"content-type", "content-length", "origin",
		},
		HPACKIndexingPolicy: "default",
		StreamPriorityMode:  "default",
		DisableCookieSplit:  &t,
		SettingsOrder:       []uint16{2, 4, 3, 5, 9},
		PseudoHeaderOrder:   []string{":method", ":scheme", ":path", ":authority"},
	}
}

func safariH3Config() *H3FingerprintConfig {
	f := false
	qpackCap := uint64(16383)
	maxField := uint64(0) // Safari omits MAX_FIELD_SECTION_SIZE
	return &H3FingerprintConfig{
		QPACKMaxTableCapacity:    &qpackCap,
		MaxFieldSectionSize:      &maxField,
		EnableDatagrams:          &f,
		QUICChromeStyleInitial:   &f, // Safari doesn't mimic Chrome's initial packet pattern
		QUICDisableHelloScramble: &f, // Safari uses default scrambling
		QUICTransportParamOrder:  "random",
		SendGreaseFrames:         &f, // Safari doesn't send GREASE frames on control stream
	}
}

func Chrome133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:             "chrome-133",
		ClientHelloID:    tls.HelloChrome_133,     // Chrome 133 with X25519MLKEM768 (correct post-quantum)
		PSKClientHelloID: tls.HelloChrome_133_PSK, // PSK for session resumption
		UserAgent:        "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="133", "Chromium";v="133", "Not_A Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   false, // Legacy preset, no proper QUIC fingerprint
	}
}

func Chrome141() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:             "chrome-141",
		ClientHelloID:    tls.HelloChrome_133,     // Chrome 133 TLS fingerprint with X25519MLKEM768
		PSKClientHelloID: tls.HelloChrome_133_PSK, // PSK for session resumption
		UserAgent:        "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   false, // Legacy preset, no proper QUIC fingerprint
	}
}

func Firefox133() *Preset {
	p := GetPlatformInfo()
	return &Preset{
		Name:          "firefox-133",
		ClientHelloID: tls.HelloFirefox_120,
		UserAgent:     "Mozilla/5.0 " + p.FirefoxUserAgentOS + " Gecko/20100101 Firefox/133.0",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
			{"accept-language", "en-US,en;q=0.5"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             true,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      131072,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 12517377,
			StreamWeight:           42,
			StreamExclusive:        false,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       firefoxH2Config(),
		SupportHTTP3:   false, // No Firefox QUIC fingerprint in utls
	}
}

func Firefox148() *Preset {
	p := GetPlatformInfo()
	firefoxUA := "Mozilla/5.0 " + p.FirefoxUserAgentOS + " Gecko/20100101 Firefox/148.0"
	if p.Platform == "Windows" {
		firefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0"
	} else if p.Platform == "macOS" {
		firefoxUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) Gecko/20100101 Firefox/148.0"
	} else {
		firefoxUA = "Mozilla/5.0 (X11; Linux x86_64; rv:148.0) Gecko/20100101 Firefox/148.0"
	}
	return &Preset{
		Name: "firefox-148",
		JA3:  "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25-256-257,0",
		JA3Extras: &JA3Extras{
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
			DelegatedCredentialAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.ECDSAWithSHA1,
			},
			ALPN: []string{"h2", "http/1.1"},
			CertCompAlgs: []tls.CertCompressionAlgo{
				tls.CertCompressionZlib,
				tls.CertCompressionBrotli,
				tls.CertCompressionZstd,
			},
			RecordSizeLimit: 0x4001,
			KeyShareCurves:  3, // Firefox sends key shares for X25519MLKEM768, X25519, P-256
		},
		UserAgent: firefoxUA,
		Headers: map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           "en-US,en;q=0.9",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Upgrade-Insecure-Requests": "1",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Priority":                  "u=0, i",
			"TE":                        "trailers",
		},
		HeaderOrder: []HeaderPair{
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"upgrade-insecure-requests", "1"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"priority", "u=0, i"},
			{"te", "trailers"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false, // Firefox 148 sends ENABLE_PUSH=0
			MaxConcurrentStreams:   0,
			InitialWindowSize:      131072,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 12517377,
			StreamWeight:           42,
			StreamExclusive:        false,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       firefoxH2Config(),
		SupportHTTP3:   false, // No Firefox QUIC fingerprint in utls
	}
}

func Chrome143() *Preset {
	p := GetPlatformInfo()
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_143_Windows
		pskClientHelloID = tls.HelloChrome_143_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_143_macOS
		pskClientHelloID = tls.HelloChrome_143_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_143_Linux
		pskClientHelloID = tls.HelloChrome_143_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-143",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,     // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK, // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome143Windows() *Preset {
	return &Preset{
		Name:                 "chrome-143-windows",
		ClientHelloID:        tls.HelloChrome_143_Windows,     // Chrome 143 Windows with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_Windows_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,        // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,    // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome143Linux() *Preset {
	return &Preset{
		Name:                 "chrome-143-linux",
		ClientHelloID:        tls.HelloChrome_143_Linux,     // Chrome 143 Linux with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_Linux_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome143macOS() *Preset {
	return &Preset{
		Name:                 "chrome-143-macos",
		ClientHelloID:        tls.HelloChrome_143_macOS,     // Chrome 143 macOS with fixed extension order
		PSKClientHelloID:     tls.HelloChrome_143_macOS_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC-specific preset for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC with PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome144() *Preset {
	p := GetPlatformInfo()
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_144_Windows
		pskClientHelloID = tls.HelloChrome_144_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_144_macOS
		pskClientHelloID = tls.HelloChrome_144_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_144_Linux
		pskClientHelloID = tls.HelloChrome_144_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-144",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome144Windows() *Preset {
	return &Preset{
		Name:                 "chrome-144-windows",
		ClientHelloID:        tls.HelloChrome_144_Windows,
		PSKClientHelloID:     tls.HelloChrome_144_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome144Linux() *Preset {
	return &Preset{
		Name:                 "chrome-144-linux",
		ClientHelloID:        tls.HelloChrome_144_Linux,
		PSKClientHelloID:     tls.HelloChrome_144_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome144macOS() *Preset {
	return &Preset{
		Name:                 "chrome-144-macos",
		ClientHelloID:        tls.HelloChrome_144_macOS,
		PSKClientHelloID:     tls.HelloChrome_144_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-GB,en-US;q=0.9,en;q=0.8",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-GB,en-US;q=0.9,en;q=0.8"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome145() *Preset {
	p := GetPlatformInfo()
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_145_Windows
		pskClientHelloID = tls.HelloChrome_145_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_145_macOS
		pskClientHelloID = tls.HelloChrome_145_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_145_Linux
		pskClientHelloID = tls.HelloChrome_145_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-145",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome doesn't send setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome145Windows() *Preset {
	return &Preset{
		Name:                 "chrome-145-windows",
		ClientHelloID:        tls.HelloChrome_145_Windows,
		PSKClientHelloID:     tls.HelloChrome_145_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome doesn't send setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome145Linux() *Preset {
	return &Preset{
		Name:                 "chrome-145-linux",
		ClientHelloID:        tls.HelloChrome_145_Linux,
		PSKClientHelloID:     tls.HelloChrome_145_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome145macOS() *Preset {
	return &Preset{
		Name:                 "chrome-145-macos",
		ClientHelloID:        tls.HelloChrome_145_macOS,
		PSKClientHelloID:     tls.HelloChrome_145_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome146() *Preset {
	p := GetPlatformInfo()
	var clientHelloID, pskClientHelloID tls.ClientHelloID
	switch p.Platform {
	case "Windows":
		clientHelloID = tls.HelloChrome_146_Windows
		pskClientHelloID = tls.HelloChrome_146_Windows_PSK
	case "macOS":
		clientHelloID = tls.HelloChrome_146_macOS
		pskClientHelloID = tls.HelloChrome_146_macOS_PSK
	default: // Linux and others
		clientHelloID = tls.HelloChrome_146_Linux
		pskClientHelloID = tls.HelloChrome_146_Linux_PSK
	}
	return &Preset{
		Name:                 "chrome-146",
		ClientHelloID:        clientHelloID,
		PSKClientHelloID:     pskClientHelloID,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 " + p.UserAgentOS + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"` + p.Platform + `"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"` + p.Platform + `"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome146Windows() *Preset {
	return &Preset{
		Name:                 "chrome-146-windows",
		ClientHelloID:        tls.HelloChrome_146_Windows,
		PSKClientHelloID:     tls.HelloChrome_146_Windows_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Windows"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Windows"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome146Linux() *Preset {
	return &Preset{
		Name:                 "chrome-146-linux",
		ClientHelloID:        tls.HelloChrome_146_Linux,
		PSKClientHelloID:     tls.HelloChrome_146_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"Linux"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"Linux"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Chrome146macOS() *Preset {
	return &Preset{
		Name:                 "chrome-146-macos",
		ClientHelloID:        tls.HelloChrome_146_macOS,
		PSKClientHelloID:     tls.HelloChrome_146_macOS_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?0",
			"sec-ch-ua-platform":        `"macOS"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?0"},
			{"sec-ch-ua-platform", `"macOS"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func Safari18() *Preset {
	return &Preset{
		Name:              "safari-18",
		ClientHelloID:     tls.HelloSafari_18,
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // Safari uses same QUIC as iOS
		UserAgent:         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // Match iOS behavior
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // Safari sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

func Chrome147Windows() *Preset {
	if p := LookupCustom("chrome-147-windows"); p != nil {
		return p
	}
	return Chrome146Windows()
}

func Chrome147Linux() *Preset {
	if p := LookupCustom("chrome-147-linux"); p != nil {
		return p
	}
	return Chrome146Linux()
}

func Chrome147macOS() *Preset {
	if p := LookupCustom("chrome-147-macos"); p != nil {
		return p
	}
	return Chrome146macOS()
}

func Chrome147() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome147Windows()
	case "macOS":
		return Chrome147macOS()
	default:
		return Chrome147Linux()
	}
}

func IOSChrome147() *Preset {
	if p := LookupCustom("chrome-147-ios"); p != nil {
		return p
	}
	return IOSChrome146()
}

func IOSChrome148() *Preset {
	if p := LookupCustom("chrome-148-ios"); p != nil {
		return p
	}
	return IOSChrome146()
}

func AndroidChrome147() *Preset {
	if p := LookupCustom("chrome-147-android"); p != nil {
		return p
	}
	return AndroidChrome146()
}

func Chrome148Windows() *Preset {
	if p := LookupCustom("chrome-148-windows"); p != nil {
		return p
	}
	return Chrome147Windows()
}

func Chrome148Linux() *Preset {
	if p := LookupCustom("chrome-148-linux"); p != nil {
		return p
	}
	return Chrome147Linux()
}

func Chrome148macOS() *Preset {
	if p := LookupCustom("chrome-148-macos"); p != nil {
		return p
	}
	return Chrome147macOS()
}

func Chrome148() *Preset {
	switch GetPlatformInfo().Platform {
	case "Windows":
		return Chrome148Windows()
	case "macOS":
		return Chrome148macOS()
	default:
		return Chrome148Linux()
	}
}

func AndroidChrome148() *Preset {
	if p := LookupCustom("chrome-148-android"); p != nil {
		return p
	}
	return AndroidChrome147()
}

func IOSChrome143() *Preset {
	return &Preset{
		Name:              "chrome-143-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/143.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

func IOSChrome144() *Preset {
	return &Preset{
		Name:              "chrome-144-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/144.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

func IOSChrome145() *Preset {
	return &Preset{
		Name:              "chrome-145-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/145.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

func IOSSafari17() *Preset {
	return &Preset{
		Name:          "safari-17-ios",
		ClientHelloID: tls.HelloIOS_14,
		UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             true,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // Safari uses m,s,p,a pseudo header order
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   false, // iOS Safari 17 doesn't have proper H3 TLS spec
	}
}

func IOSSafari18() *Preset {
	return &Preset{
		Name:              "safari-18-ios",
		ClientHelloID:     tls.HelloIOS_18,
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Safari QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-dest", "document"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-user", "?1"},
			{"accept-language", "en-US,en;q=0.9"},
			{"accept-encoding", "gzip, deflate, br"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false, // iOS 18 sends ENABLE_PUSH=0
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true, // iOS sends NO_RFC7540_PRIORITIES=1
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

func AndroidChrome143() *Preset {
	return &Preset{
		Name:                 "chrome-143-android",
		ClientHelloID:        tls.HelloChrome_143_Linux,     // Android Chrome uses Chrome's TLS
		PSKClientHelloID:     tls.HelloChrome_143_Linux_PSK, // PSK for session resumption
		QUICClientHelloID:    tls.HelloChrome_143_QUIC,      // QUIC for HTTP/3
		QUICPSKClientHelloID: tls.HelloChrome_143_QUIC_PSK,  // QUIC PSK for session resumption
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""}, // Placeholder - actual value set from preset.UserAgent
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func AndroidChrome144() *Preset {
	return &Preset{
		Name:                 "chrome-144-android",
		ClientHelloID:        tls.HelloChrome_144_Linux,
		PSKClientHelloID:     tls.HelloChrome_144_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_144_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_144_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func IOSChrome146() *Preset {
	return &Preset{
		Name:              "chrome-146-ios",
		ClientHelloID:     tls.HelloIOS_18,      // iOS Chrome uses Safari's TLS (WebKit requirement)
		QUICClientHelloID: tls.HelloIOS_18_QUIC, // iOS Chrome uses Safari's QUIC for H3
		UserAgent:         "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/146.0.6917.0 Mobile/15E148 Safari/604.1",
		Headers: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Dest":  "document",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Mode":  "navigate",
			"Accept-Language": "en-US,en;q=0.9",
			"Sec-Fetch-User":  "?1",
		},
		HeaderOrder: []HeaderPair{
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br"},
			{"sec-fetch-mode", "navigate"},
			{"user-agent", ""},
			{"accept-language", "en-US,en;q=0.9"},
			{"sec-fetch-user", "?1"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        4096,
			EnablePush:             false,
			MaxConcurrentStreams:   100,
			InitialWindowSize:      2097152,
			MaxFrameSize:           16384,
			MaxHeaderListSize:      0,
			ConnectionWindowUpdate: 10485760,
			StreamWeight:           255,
			StreamExclusive:        false,
			NoRFC7540Priorities:    true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       safariH2Config(),
		H3Config:       safariH3Config(),
		SupportHTTP3:   true,
	}
}

func AndroidChrome146() *Preset {
	return &Preset{
		Name:                 "chrome-146-android",
		ClientHelloID:        tls.HelloChrome_146_Linux,
		PSKClientHelloID:     tls.HelloChrome_146_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_146_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_146_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0,
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

func AndroidChrome145() *Preset {
	return &Preset{
		Name:                 "chrome-145-android",
		ClientHelloID:        tls.HelloChrome_145_Linux,
		PSKClientHelloID:     tls.HelloChrome_145_Linux_PSK,
		QUICClientHelloID:    tls.HelloChrome_145_QUIC,
		QUICPSKClientHelloID: tls.HelloChrome_145_QUIC_PSK,
		UserAgent:            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Mobile Safari/537.36",
		Headers: map[string]string{
			"sec-ch-ua":                 `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`,
			"sec-ch-ua-mobile":          "?1",
			"sec-ch-ua-platform":        `"Android"`,
			"Upgrade-Insecure-Requests": "1",
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-User":            "?1",
			"Sec-Fetch-Dest":            "document",
			"Accept-Encoding":           "gzip, deflate, br, zstd",
			"Accept-Language":           "en-US,en;q=0.9",
			"Priority":                  "u=0, i",
		},
		HeaderOrder: []HeaderPair{
			{"sec-ch-ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`},
			{"sec-ch-ua-mobile", "?1"},
			{"sec-ch-ua-platform", `"Android"`},
			{"upgrade-insecure-requests", "1"},
			{"user-agent", ""},
			{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
			{"sec-fetch-site", "none"},
			{"sec-fetch-mode", "navigate"},
			{"sec-fetch-user", "?1"},
			{"sec-fetch-dest", "document"},
			{"accept-encoding", "gzip, deflate, br, zstd"},
			{"accept-language", "en-US,en;q=0.9"},
			{"priority", "u=0, i"},
		},
		HTTP2Settings: HTTP2Settings{
			HeaderTableSize:        65536,
			EnablePush:             false,
			MaxConcurrentStreams:   0,
			InitialWindowSize:      6291456,
			MaxFrameSize:           0, // Chrome omits setting 5 (16384 is RFC default)
			MaxHeaderListSize:      262144,
			ConnectionWindowUpdate: 15663105,
			StreamWeight:           256,
			StreamExclusive:        true,
		},
		TCPFingerprint: TCPFingerprint{},
		H2Config:       chromeH2Config(),
		SupportHTTP3:   true,
	}
}

var presets = map[string]func() *Preset{
	"chrome-133":         Chrome133,
	"chrome-141":         Chrome141,
	"chrome-143":         Chrome143,
	"chrome-143-windows": Chrome143Windows,
	"chrome-143-linux":   Chrome143Linux,
	"chrome-143-macos":   Chrome143macOS,
	"chrome-144":         Chrome144,
	"chrome-144-windows": Chrome144Windows,
	"chrome-144-linux":   Chrome144Linux,
	"chrome-144-macos":   Chrome144macOS,
	"chrome-145":         Chrome145,
	"chrome-145-windows": Chrome145Windows,
	"chrome-145-linux":   Chrome145Linux,
	"chrome-145-macos":   Chrome145macOS,
	"chrome-146":         Chrome146,
	"chrome-146-windows": Chrome146Windows,
	"chrome-146-linux":   Chrome146Linux,
	"chrome-146-macos":   Chrome146macOS,
	"chrome-147":         Chrome147,
	"chrome-147-windows": Chrome147Windows,
	"chrome-147-linux":   Chrome147Linux,
	"chrome-147-macos":   Chrome147macOS,
	"firefox-133":        Firefox133,
	"firefox-148":        Firefox148,
	"safari-18":          Safari18,
	"chrome-143-ios":     IOSChrome143,
	"chrome-144-ios":     IOSChrome144,
	"chrome-145-ios":     IOSChrome145,
	"chrome-146-ios":     IOSChrome146,
	"safari-17-ios":      IOSSafari17,
	"safari-18-ios":      IOSSafari18,
	"chrome-143-android": AndroidChrome143,
	"chrome-144-android": AndroidChrome144,
	"chrome-145-android": AndroidChrome145,
	"chrome-146-android": AndroidChrome146,
	"chrome-147-ios":     IOSChrome147,
	"chrome-147-android": AndroidChrome147,
	"chrome-148-ios":     IOSChrome148,
	"chrome-148":         Chrome148,
	"chrome-148-windows": Chrome148Windows,
	"chrome-148-linux":   Chrome148Linux,
	"chrome-148-macos":   Chrome148macOS,
	"chrome-148-android": AndroidChrome148,

	"chrome-latest":         Chrome148,
	"chrome-latest-windows": Chrome148Windows,
	"chrome-latest-linux":   Chrome148Linux,
	"chrome-latest-macos":   Chrome148macOS,
	"firefox-latest":        Firefox148,
	"safari-latest":         Safari18,
	"chrome-latest-ios":     IOSChrome148,
	"safari-latest-ios":     IOSSafari18,
	"chrome-latest-android": AndroidChrome148,

	"ios-chrome-143":        IOSChrome143,
	"ios-chrome-144":        IOSChrome144,
	"ios-chrome-145":        IOSChrome145,
	"ios-chrome-146":        IOSChrome146,
	"ios-chrome-147":        IOSChrome147,
	"ios-chrome-148":        IOSChrome148,
	"ios-safari-17":         IOSSafari17,
	"ios-safari-18":         IOSSafari18,
	"android-chrome-143":    AndroidChrome143,
	"android-chrome-144":    AndroidChrome144,
	"android-chrome-145":    AndroidChrome145,
	"android-chrome-146":    AndroidChrome146,
	"android-chrome-147":    AndroidChrome147,
	"android-chrome-148":    AndroidChrome148,
	"ios-chrome-latest":     IOSChrome148,
	"ios-safari-latest":     IOSSafari18,
	"android-chrome-latest": AndroidChrome148,
}

func Get(name string) *Preset {
	if p := LookupCustom(name); p != nil {
		return p
	}
	if fn, ok := presets[name]; ok {
		return fn()
	}
	return Chrome146()
}

func GetStrict(name string) *Preset {
	if p := LookupCustom(name); p != nil {
		return p
	}
	if fn, ok := presets[name]; ok {
		return fn()
	}
	return nil
}

func Available() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	return names
}

type PresetInfo struct {
	Protocols []string `json:"protocols"`
}

func AvailableWithInfo() map[string]PresetInfo {
	result := make(map[string]PresetInfo, len(presets))
	for name, presetFn := range presets {
		p := presetFn()
		protocols := []string{"h1", "h2"}
		if p.SupportHTTP3 {
			protocols = append(protocols, "h3")
		}
		result[name] = PresetInfo{Protocols: protocols}
	}
	return result
}
