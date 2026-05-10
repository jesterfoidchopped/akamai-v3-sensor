package transport

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/dns"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/proxy"
	http "github.com/sardanioss/http"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	"github.com/sardanioss/quic-go/quicvarint"
	"github.com/sardanioss/udpbara"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

const (
	settingQPACKMaxTableCapacity = 0x1
	settingMaxFieldSectionSize   = 0x6
	settingQPACKBlockedStreams   = 0x7
	settingH3Datagram            = 0x33
)

const (
	tpVersionInformation      = 0x11   // RFC 9368 version negotiation
	tpGoogleVersion           = 0x4752 // Google's custom version param (18258)
	tpInitialRTT              = 0x3127 // initial_rtt (12583) - Chrome's cached SRTT
	tpGoogleConnectionOptions = 0x3128 // Google's connection options param (12584)
)

var (
	rttMu           sync.Mutex
	rttMeasured     bool
	cachedRTTParams map[uint64][]byte // cached Chrome params with measured RTT
)

func BuildChromeTransportParams() map[uint64][]byte {
	params := make(map[uint64][]byte)

	versionInfo := make([]byte, 0, 12)
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001)
	greaseVersion := generateGREASEVersion()
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, greaseVersion)
	versionInfo = binary.BigEndian.AppendUint32(versionInfo, 0x00000001)
	params[tpVersionInformation] = versionInfo

	googleVersion := make([]byte, 4)
	binary.BigEndian.PutUint32(googleVersion, 0x00000001) // QUICv1
	params[tpGoogleVersion] = googleVersion

	params[tpGoogleConnectionOptions] = []byte("ORIG")

	initialRTT := make([]byte, 0, 8)
	initialRTT = quicvarint.Append(initialRTT, 100000) // 100ms fallback
	params[tpInitialRTT] = initialRTT

	return params
}

func MeasureInitialRTT(ctx context.Context, host string, port int) map[uint64][]byte {
	rttMu.Lock()
	defer rttMu.Unlock()
	if rttMeasured {
		return cachedRTTParams
	}
	rttMeasured = true

	cachedRTTParams = BuildChromeTransportParams()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	rtt := time.Since(start)
	if conn != nil {
		conn.Close()
	}
	if err != nil {
		return cachedRTTParams // keep default 100ms
	}

	rttValue := make([]byte, 0, 8)
	rttValue = quicvarint.Append(rttValue, uint64(rtt.Microseconds()))
	cachedRTTParams[tpInitialRTT] = rttValue
	return cachedRTTParams
}

func MeasureAndSetInitialRTT(ctx context.Context, host string, port int) {
	params := MeasureInitialRTT(ctx, host, port)
	quic.SetAdditionalTransportParameters(params)
}

func ResetInitialRTT() {
	rttMu.Lock()
	defer rttMu.Unlock()
	rttMeasured = false
	cachedRTTParams = nil
}

func AdditionalTransportParamsForPreset(preset *fingerprint.Preset, ctx context.Context, host string, port int) map[uint64][]byte {
	if preset == nil {
		return nil
	}
	order := preset.H3QUICTransportParamOrder()
	if order != "chrome" {
		return nil
	}
	if ctx != nil && host != "" && port > 0 {
		return MeasureInitialRTT(ctx, host, port)
	}
	return BuildChromeTransportParams()
}

func generateGREASEVersion() uint32 {
	nibble := byte(rand.Intn(16))
	return uint32(nibble)<<28 | 0x0a000000 |
		uint32(nibble)<<20 | 0x000a0000 |
		uint32(nibble)<<12 | 0x00000a00 |
		uint32(nibble)<<4 | 0x0000000a
}

type proxyQUICConn struct {
	udpConn   *udpbara.Connection
	quicTr    *quic.Transport
	closeOnce sync.Once
}

type HTTP3Transport struct {
	transport *http3.Transport
	preset    *fingerprint.Preset
	dnsCache  *dns.Cache

	sessionCache tls.ClientSessionCache

	cachedClientHelloSpec    *utls.ClientHelloSpec
	cachedClientHelloSpecPSK *utls.ClientHelloSpec

	cachedClientHelloSpecInner    *utls.ClientHelloSpec
	cachedClientHelloSpecInnerPSK *utls.ClientHelloSpec

	shuffleSeed int64

	requestCount int64
	dialCount    int64 // Number of times dialQUIC was called (new connections)
	mu           sync.RWMutex

	quicConfig *quic.Config
	tlsConfig  *tls.Config

	proxyConfig   *ProxyConfig
	udpbaraTunnel *udpbara.Tunnel // SOCKS5 UDP relay tunnel (shared across dials)
	proxyConns    []*proxyQUICConn
	proxyConnsMu  sync.Mutex
	quicTransport *quic.Transport // Only used for direct connections

	masqueConn *proxy.MASQUEConn

	config *TransportConfig

	echConfigCache   map[string][]byte
	echConfigCacheMu sync.RWMutex

	insecureSkipVerify bool

	disableECH bool

	localAddr string
}

func (t *HTTP3Transport) SetInsecureSkipVerify(skip bool) {
	t.insecureSkipVerify = skip
	if t.tlsConfig != nil {
		t.tlsConfig.InsecureSkipVerify = skip
	}
}

func (t *HTTP3Transport) SetLocalAddr(addr string) {
	t.localAddr = addr
}

func (t *HTTP3Transport) SetDisableECH(disable bool) {
	t.disableECH = disable
}

func (t *HTTP3Transport) hasSessionForHost(host string) bool {
	if t.sessionCache == nil {
		return false
	}
	cache, ok := t.sessionCache.(*PersistableSessionCache)
	if !ok {
		return false
	}
	_, found := cache.Get(host)
	return found
}

func (t *HTTP3Transport) getSpecForHost(host string) *utls.ClientHelloSpec {
	if t.cachedClientHelloSpecPSK != nil && t.hasSessionForHost(host) {
		return t.cachedClientHelloSpecPSK
	}
	return t.cachedClientHelloSpec
}

func (t *HTTP3Transport) getInnerSpecForHost(host string) *utls.ClientHelloSpec {
	if t.cachedClientHelloSpecInnerPSK != nil && t.hasSessionForHost(host) {
		return t.cachedClientHelloSpecInnerPSK
	}
	return t.cachedClientHelloSpecInner
}

func NewHTTP3Transport(preset *fingerprint.Preset, dnsCache *dns.Cache) (*HTTP3Transport, error) {
	return NewHTTP3TransportWithTransportConfig(preset, dnsCache, nil)
}

func NewHTTP3TransportWithTransportConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, config *TransportConfig) (*HTTP3Transport, error) {
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h3",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP3Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		config:         config,
		echConfigCache: make(map[string][]byte), // Cache for ECH configs (for session resumption)
	}

	var clientHelloID *utls.ClientHelloID
	if preset.QUICClientHelloID.Client != "" {
		clientHelloID = &preset.QUICClientHelloID
	} else if preset.ClientHelloID.Client != "" {
		clientHelloID = &preset.ClientHelloID
	}

	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpec = &spec
		}
	}

	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			t.cachedClientHelloSpecPSK = &pskSpec
		}
	}

	var keyLogWriter io.Writer
	if config != nil && config.KeyLogWriter != nil {
		keyLogWriter = config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	if t.cachedClientHelloSpecPSK != nil {
		t.tlsConfig.ClientSessionCache = t.sessionCache
	}

	quicIdleTimeout := 30 * time.Second
	if config != nil && config.QuicIdleTimeout > 0 {
		quicIdleTimeout = config.QuicIdleTimeout
	}

	t.quicConfig = t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)

	additionalSettings := t.buildH3AdditionalSettings()

	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	var localUDPAddr *net.UDPAddr
	if t.localAddr != "" {
		localUDPAddr = &net.UDPAddr{IP: net.ParseIP(t.localAddr)}
	} else {
		localUDPAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	udpConn, err := ListenUDPWithLocalAddr("udp", localUDPAddr, t.localAddr)
	if err != nil {
		if t.localAddr != "" {
			return nil, fmt.Errorf("failed to create UDP socket for %s: %w", t.localAddr, err)
		}
		localUDPAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
		udpConn, err = ListenUDPWithLocalAddr("udp6", localUDPAddr, t.localAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket (IPv4 and IPv6 both failed): %w", err)
		}
	}
	t.quicTransport = &quic.Transport{
		Conn:                         udpConn,
		ConnectionIDLength:           t.preset.H3QUICConnectionIDLength(),
		AllowZeroLengthConnectionIDs: true,
	}

	t.transport = t.buildHTTP3Transport(t.dialQUIC, additionalSettings)

	return t, nil
}

func NewHTTP3TransportWithProxy(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig) (*HTTP3Transport, error) {
	return NewHTTP3TransportWithConfig(preset, dnsCache, proxyConfig, nil)
}

func NewHTTP3TransportWithConfig(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig, config *TransportConfig) (*HTTP3Transport, error) {
	if proxyConfig == nil || proxyConfig.URL == "" {
		return nil, fmt.Errorf("NewHTTP3TransportWithConfig requires a proxy; use NewHTTP3TransportWithTransportConfig for direct connections")
	}
	if proxyConfig.URL != "" {
		proxyURL, err := url.Parse(proxyConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		if proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
			return nil, fmt.Errorf("HTTP/3 requires SOCKS5 proxy for UDP relay, got: %s", proxyURL.Scheme)
		}
	}

	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h3",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP3Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		proxyConfig:    proxyConfig,
		config:         config,
		echConfigCache: make(map[string][]byte),
	}

	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	var clientHelloID *utls.ClientHelloID
	if preset.QUICClientHelloID.Client != "" {
		clientHelloID = &preset.QUICClientHelloID
	} else if preset.ClientHelloID.Client != "" {
		clientHelloID = &preset.ClientHelloID
	}

	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpec = &spec
		}
	}

	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			t.cachedClientHelloSpecPSK = &pskSpec
		}
	}

	var keyLogWriter io.Writer
	if config != nil && config.KeyLogWriter != nil {
		keyLogWriter = config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	if t.cachedClientHelloSpecPSK != nil {
		t.tlsConfig.ClientSessionCache = t.sessionCache
	}

	quicIdleTimeout := 30 * time.Second
	if config != nil && config.QuicIdleTimeout > 0 {
		quicIdleTimeout = config.QuicIdleTimeout
	}

	t.quicConfig = t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)

	if proxyConfig != nil && proxyConfig.URL != "" {
		tunnel, err := udpbara.NewTunnel(proxyConfig.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 tunnel: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := tunnel.ConnectContext(ctx); err != nil {
			tunnel.Close()
			return nil, fmt.Errorf("SOCKS5 proxy does not support UDP relay (required for HTTP/3): %w", err)
		}
		t.udpbaraTunnel = tunnel
	}

	additionalSettings := t.buildH3AdditionalSettings()

	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.udpbaraTunnel != nil {
		dialFunc = t.dialQUICWithProxy
	} else {
		dialFunc = t.dialQUIC
	}
	t.transport = t.buildHTTP3Transport(dialFunc, additionalSettings)

	return t, nil
}

func NewHTTP3TransportWithMASQUE(preset *fingerprint.Preset, dnsCache *dns.Cache, proxyConfig *ProxyConfig, config *TransportConfig) (*HTTP3Transport, error) {
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	var sessionCache *PersistableSessionCache
	if config != nil && config.SessionCacheBackend != nil {
		sessionCache = NewPersistableSessionCacheWithBackend(
			config.SessionCacheBackend,
			preset.Name,
			"h3",
			config.SessionCacheErrorCallback,
		)
	} else {
		sessionCache = NewPersistableSessionCache()
	}

	t := &HTTP3Transport{
		preset:         preset,
		dnsCache:       dnsCache,
		sessionCache:   sessionCache,
		shuffleSeed:    shuffleSeed,
		proxyConfig:    proxyConfig,
		config:         config,
		echConfigCache: make(map[string][]byte),
	}

	if config != nil && config.LocalAddr != "" {
		t.localAddr = config.LocalAddr
	}

	var clientHelloID *utls.ClientHelloID
	if preset.QUICClientHelloID.Client != "" {
		clientHelloID = &preset.QUICClientHelloID
	} else if preset.ClientHelloID.Client != "" {
		clientHelloID = &preset.ClientHelloID
	}

	if clientHelloID != nil {
		spec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpec = &spec
		}
		innerSpec, err := utls.UTLSIdToSpecWithSeed(*clientHelloID, shuffleSeed)
		if err == nil {
			t.cachedClientHelloSpecInner = &innerSpec
		}
	}

	if preset.QUICPSKClientHelloID.Client != "" {
		if pskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			t.cachedClientHelloSpecPSK = &pskSpec
		}
		if innerPskSpec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			t.cachedClientHelloSpecInnerPSK = &innerPskSpec
		}
	}

	var keyLogWriter io.Writer
	if config != nil && config.KeyLogWriter != nil {
		keyLogWriter = config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	t.tlsConfig = &tls.Config{
		NextProtos:         []string{http3.NextProtoH3},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	if t.cachedClientHelloSpecPSK != nil {
		t.tlsConfig.ClientSessionCache = t.sessionCache
	}

	quicIdleTimeout := 30 * time.Second
	if config != nil && config.QuicIdleTimeout > 0 {
		quicIdleTimeout = config.QuicIdleTimeout
	}

	t.quicConfig = t.buildQUICConfig(clientHelloID, quicIdleTimeout, 1350)

	masqueConn, err := proxy.NewMASQUEConn(proxyConfig.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create MASQUE connection: %w", err)
	}
	t.masqueConn = masqueConn

	additionalSettings := t.buildH3AdditionalSettings()

	t.transport = t.buildHTTP3Transport(t.dialQUICWithMASQUE, additionalSettings)

	return t, nil
}

func (t *HTTP3Transport) dialQUICWithMASQUE(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	connectHost := t.getConnectHost(host)

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	err = t.masqueConn.EstablishWithQUICConfig(ctx, connectHost, portInt, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("MASQUE tunnel establishment failed: %w", err)
	}

	ip, err := t.dnsCache.ResolveOne(ctx, connectHost)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", connectHost, err)
	}

	targetAddr := &net.UDPAddr{IP: ip, Port: portInt}

	t.masqueConn.SetResolvedTarget(targetAddr)

	tlsCfgCopy := tlsCfg.Clone()
	tlsCfgCopy.ServerName = host
	if t.cachedClientHelloSpecPSK != nil {
		tlsCfgCopy.ClientSessionCache = t.sessionCache
	}

	echConfigList := t.getECHConfig(ctx, host)

	var clientHelloID *utls.ClientHelloID
	if t.preset.QUICClientHelloID.Client != "" {
		clientHelloID = &t.preset.QUICClientHelloID
	} else if t.preset.ClientHelloID.Client != "" {
		clientHelloID = &t.preset.ClientHelloID
	}

	innerSpec := t.getInnerSpecForHost(host)

	quicIdleTimeout := 30 * time.Second
	if t.config != nil && t.config.QuicIdleTimeout > 0 {
		quicIdleTimeout = t.config.QuicIdleTimeout
	}
	keepAlivePeriod := quicIdleTimeout / 2

	cfgCopy := &quic.Config{
		MaxIdleTimeout:                 quicIdleTimeout,
		KeepAlivePeriod:                keepAlivePeriod,
		MaxIncomingStreams:             t.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:          t.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                      t.preset.H3QUICAllow0RTT(),
		EnableDatagrams:                true, // Always true at QUIC level
		InitialPacketSize:              1200, // MASQUE inner constraint (not fingerprint)
		DisablePathMTUDiscovery:        true, // MASQUE tunnel constraint
		DisableClientHelloScrambling:   t.preset.H3QUICDisableHelloScramble(),
		InitialStreamReceiveWindow:     512 * 1024,           // MASQUE flow control
		MaxStreamReceiveWindow:         6 * 1024 * 1024,      // MASQUE flow control
		InitialConnectionReceiveWindow: 15 * 1024 * 1024 / 2, // MASQUE flow control
		MaxConnectionReceiveWindow:     15 * 1024 * 1024,     // MASQUE flow control
		TransportParameterOrder:        resolveTransportParamOrder(t.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed:  t.shuffleSeed,
		ClientHelloID:                  clientHelloID,
		CachedClientHelloSpec:          innerSpec, // Separate spec for consistent JA4, uses PSK for resumed
		ECHConfigList:                  echConfigList,
		AdditionalTransportParameters:  AdditionalTransportParamsForPreset(t.preset, nil, "", 0),
		MaxDatagramFrameSize:           t.preset.H3QUICMaxDatagramFrameSize(),
	}

	return quic.DialEarly(ctx, t.masqueConn, targetAddr, tlsCfgCopy, cfgCopy)
}

func (t *HTTP3Transport) dialQUICWithProxy(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	connectHost := t.getConnectHost(host)
	target := net.JoinHostPort(connectHost, port)

	echConfigList := t.getECHConfig(ctx, host)

	udpConn, err := t.udpbaraTunnel.DialContext(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("udpbara dial failed: %w", err)
	}

	qt := &quic.Transport{
		Conn:                         udpConn.PacketConn(),
		ConnectionIDLength:           t.preset.H3QUICConnectionIDLength(),
		AllowZeroLengthConnectionIDs: true,
	}

	pc := &proxyQUICConn{udpConn: udpConn, quicTr: qt}
	t.proxyConnsMu.Lock()
	t.proxyConns = append(t.proxyConns, pc)
	t.proxyConnsMu.Unlock()

	tlsCfgCopy := t.tlsConfig.Clone()
	tlsCfgCopy.ServerName = host
	if t.cachedClientHelloSpecPSK != nil {
		tlsCfgCopy.ClientSessionCache = t.sessionCache
	}

	cfgCopy := t.quicConfig.Clone()
	cfgCopy.CachedClientHelloSpec = t.getSpecForHost(host)
	if echConfigList != nil {
		cfgCopy.ECHConfigList = echConfigList
	}

	conn, err := qt.DialEarly(ctx, udpConn.RelayAddr(), tlsCfgCopy, cfgCopy)
	if err != nil {
		closeProxyConn(pc)
		t.removeProxyConn(pc)
		return nil, err
	}

	go func() {
		<-conn.Context().Done()
		closeProxyConn(pc)
		t.removeProxyConn(pc)
	}()

	return conn, nil
}

func (t *HTTP3Transport) raceQUICDial(ctx context.Context, host string, ipv6Addrs, ipv4Addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	echConfigList := t.getECHConfig(ctx, host)
	return t.raceQUICDialWithECH(ctx, host, ipv6Addrs, ipv4Addrs, tlsCfg, cfg, echConfigList)
}

func (t *HTTP3Transport) raceQUICDialWithECH(ctx context.Context, host string, ipv6Addrs, ipv4Addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config, echConfigList []byte) (*quic.Conn, error) {
	if len(ipv6Addrs) == 0 && len(ipv4Addrs) == 0 {
		return nil, fmt.Errorf("no addresses to dial")
	}

	pskSpec := cfg.CachedClientHelloSpec

	makeConfig := func() *quic.Config {
		cfgCopy := cfg.Clone()
		cfgCopy.CachedClientHelloSpec = pskSpec
		if echConfigList != nil {
			cfgCopy.ECHConfigList = echConfigList
		}
		return cfgCopy
	}

	if len(ipv6Addrs) == 0 {
		return t.dialFirstSuccessful(ctx, ipv4Addrs, tlsCfg, makeConfig())
	}
	if len(ipv4Addrs) == 0 {
		return t.dialFirstSuccessful(ctx, ipv6Addrs, tlsCfg, makeConfig())
	}

	ipv6Timeout := 2 * time.Second // Give IPv6 a reasonable chance
	ipv6Ctx, ipv6Cancel := context.WithTimeout(ctx, ipv6Timeout)

	conn, _ := t.dialFirstSuccessful(ipv6Ctx, ipv6Addrs, tlsCfg, makeConfig())
	ipv6Cancel()

	if conn != nil {
		return conn, nil
	}

	return t.dialFirstSuccessful(ctx, ipv4Addrs, tlsCfg, makeConfig())
}

func (t *HTTP3Transport) dialFirstSuccessful(ctx context.Context, addrs []*net.UDPAddr, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	var lastErr error
	for i, addr := range addrs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		remaining := len(addrs) - i
		perAddrTimeout := 10 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			budget := time.Until(deadline) / time.Duration(remaining)
			if budget < perAddrTimeout {
				perAddrTimeout = budget
			}
		}
		addrCtx, addrCancel := context.WithTimeout(ctx, perAddrTimeout)
		conn, err := t.quicTransport.DialEarly(addrCtx, addr, tlsCfg, cfg)
		addrCancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func resolveTransportParamOrder(order string) quic.TransportParameterOrderMode {
	switch order {
	case "chrome":
		return quic.TransportParameterOrderChrome
	case "random":
		return quic.TransportParameterOrderDefault
	default:
		return quic.TransportParameterOrderChrome
	}
}

func (t *HTTP3Transport) buildQUICConfig(clientHelloID *utls.ClientHelloID, quicIdleTimeout time.Duration, initialPacketSizeOverride uint16) *quic.Config {
	keepAlivePeriod := quicIdleTimeout / 2
	initialPacketSize := t.preset.H3QUICInitialPacketSize()
	if initialPacketSizeOverride > 0 {
		initialPacketSize = initialPacketSizeOverride
	}
	cfg := &quic.Config{
		MaxIdleTimeout:                quicIdleTimeout,
		KeepAlivePeriod:               keepAlivePeriod,
		MaxIncomingStreams:            t.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:         t.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                     t.preset.H3QUICAllow0RTT(),
		EnableDatagrams:               true, // Always true at QUIC level (original behavior); H3 SETTINGS controls per-browser advertisement
		InitialPacketSize:             initialPacketSize,
		DisablePathMTUDiscovery:       false,
		DisableClientHelloScrambling:  t.preset.H3QUICDisableHelloScramble(),
		ChromeStyleInitialPackets:     t.preset.H3QUICChromeStyleInitial(),
		ClientHelloID:                 clientHelloID,
		CachedClientHelloSpec:         t.cachedClientHelloSpec,
		TransportParameterOrder:       resolveTransportParamOrder(t.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed: t.shuffleSeed,
		AdditionalTransportParameters: AdditionalTransportParamsForPreset(t.preset, nil, "", 0),
		MaxDatagramFrameSize:          t.preset.H3QUICMaxDatagramFrameSize(),
	}
	if v := t.preset.H3QUICInitialStreamReceiveWindow(); v != 0 {
		cfg.InitialStreamReceiveWindow = v
	}
	if v := t.preset.H3QUICInitialConnectionReceiveWindow(); v != 0 {
		cfg.InitialConnectionReceiveWindow = v
	}
	return cfg
}

func (t *HTTP3Transport) buildH3AdditionalSettings() map[uint64]uint64 {
	greaseSettingID := generateGREASESettingID()
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	settings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: t.preset.H3QPACKMaxTableCapacity(),
		settingQPACKBlockedStreams:   t.preset.H3QPACKBlockedStreams(),
		greaseSettingID:              greaseSettingValue,
	}

	if maxField := t.preset.H3MaxFieldSectionSize(); maxField > 0 {
		settings[settingMaxFieldSectionSize] = maxField
	}
	if t.preset.H3EnableDatagrams() {
		settings[settingH3Datagram] = 1
	}

	return settings
}

func (t *HTTP3Transport) buildHTTP3Transport(dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error), additionalSettings map[uint64]uint64) *http3.Transport {
	return &http3.Transport{
		TLSClientConfig:        t.tlsConfig,
		QUICConfig:             t.quicConfig,
		Dial:                   dialFunc,
		EnableDatagrams:        true, // Always true at HTTP/3 level (original behavior); H3 SETTINGS controls per-browser advertisement
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: int(t.preset.H3MaxResponseHeaderBytes()),
		SendGreaseFrames:       t.preset.H3SendGreaseFrames(),
	}
}

func generateGREASESettingID() uint64 {
	n := uint64(1000000000 + rand.Int63n(9000000000))
	return 0x1f*n + 0x21
}

func (t *HTTP3Transport) dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	connectHost := t.getConnectHost(host)

	var ips []net.IP
	var dnsErr error
	var echConfigList []byte

	if t.disableECH {
		ips, dnsErr = t.dnsCache.Resolve(ctx, connectHost)
	} else {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			ips, dnsErr = t.dnsCache.Resolve(ctx, connectHost)
		}()

		go func() {
			defer wg.Done()
			echConfigList = t.getECHConfig(ctx, host)
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if dnsErr != nil {
		return nil, fmt.Errorf("DNS resolution failed for %s: %w", connectHost, dnsErr)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", connectHost)
	}

	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	if params := AdditionalTransportParamsForPreset(t.preset, ctx, ips[0].String(), portInt); params != nil {
		t.quicConfig.AdditionalTransportParameters = params
	}

	if t.localAddr != "" {
		localIP := net.ParseIP(t.localAddr)
		if localIP != nil {
			isLocalIPv6 := localIP.To4() == nil
			var filtered []net.IP
			for _, ip := range ips {
				if (ip.To4() == nil) == isLocalIPv6 {
					filtered = append(filtered, ip)
				}
			}
			ips = filtered
			if len(ips) == 0 {
				family := "IPv4"
				if isLocalIPv6 {
					family = "IPv6"
				}
				return nil, fmt.Errorf("no %s addresses found for host (local address is %s)", family, t.localAddr)
			}
		}
	}

	var ipv4Addrs, ipv6Addrs []*net.UDPAddr
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4Addrs = append(ipv4Addrs, &net.UDPAddr{IP: ip.To4(), Port: portInt})
		} else if ip.To16() != nil {
			ipv6Addrs = append(ipv6Addrs, &net.UDPAddr{IP: ip, Port: portInt})
		}
	}

	tlsCfgCopy := t.tlsConfig.Clone()
	tlsCfgCopy.ServerName = host
	if t.cachedClientHelloSpecPSK != nil {
		tlsCfgCopy.ClientSessionCache = t.sessionCache
	}

	cfgCopy := t.quicConfig.Clone()

	cfgCopy.CachedClientHelloSpec = t.getSpecForHost(host)

	return t.raceQUICDialWithECH(ctx, host, ipv6Addrs, ipv4Addrs, tlsCfgCopy, cfgCopy, echConfigList)
}

func (t *HTTP3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.requestCount++
	reqNum := t.requestCount
	dialsBefore := t.dialCount
	t.mu.Unlock()

	tlsOnly := t.config != nil && t.config.TLSOnly
	if !tlsOnly {
		if len(t.preset.HeaderOrder) > 0 {
			for _, hp := range t.preset.HeaderOrder {
				if req.Header.Get(hp.Key) == "" {
					req.Header.Set(hp.Key, hp.Value)
				}
			}
		} else {
			for key, value := range t.preset.Headers {
				if req.Header.Get(key) == "" {
					req.Header.Set(key, value)
				}
			}
		}

		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", t.preset.UserAgent)
		}
	}

	requestHost := req.URL.Hostname()
	connectHost := t.getConnectHost(requestHost)
	if connectHost != requestHost {
		if req.Host == "" {
			req.Host = req.URL.Host
		}
		origURLHost := req.URL.Host
		if req.URL.Port() != "" {
			req.URL.Host = net.JoinHostPort(connectHost, req.URL.Port())
		} else {
			req.URL.Host = connectHost
		}
		defer func() { req.URL.Host = origURLHost }()
	}

	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	var resp *http.Response
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = transport.RoundTrip(req)
		if err == nil || !is0RTTRejectedError(err) {
			break
		}
		closeWithTimeout(transport, 3*time.Second)
		t.recreateTransport()
		t.mu.RLock()
		transport = t.transport
		t.mu.RUnlock()
	}

	t.mu.RLock()
	dialsAfter := t.dialCount
	t.mu.RUnlock()

	_ = reqNum
	_ = dialsBefore
	_ = dialsAfter

	return resp, err
}

func (t *HTTP3Transport) IsConnectionReused(host string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.requestCount > t.dialCount
}

func (t *HTTP3Transport) GetDialCount() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dialCount
}

func (t *HTTP3Transport) GetRequestCount() int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.requestCount
}

func (t *HTTP3Transport) removeProxyConn(pc *proxyQUICConn) {
	t.proxyConnsMu.Lock()
	defer t.proxyConnsMu.Unlock()
	for i, c := range t.proxyConns {
		if c == pc {
			t.proxyConns = append(t.proxyConns[:i], t.proxyConns[i+1:]...)
			return
		}
	}
}

func closeProxyConn(pc *proxyQUICConn) {
	pc.closeOnce.Do(func() {
		closeWithTimeout(pc.quicTr, 3*time.Second)
		pc.udpConn.Close()
	})
}

func (t *HTTP3Transport) closeAllProxyConns() {
	t.proxyConnsMu.Lock()
	conns := t.proxyConns
	t.proxyConns = nil
	t.proxyConnsMu.Unlock()
	for _, c := range conns {
		closeProxyConn(c)
	}
}

func (t *HTTP3Transport) Close() error {
	t.mu.RLock()
	transport := t.transport
	t.mu.RUnlock()

	closeWithTimeout(transport, 3*time.Second)

	if t.quicTransport != nil {
		closeWithTimeout(t.quicTransport, 3*time.Second)
	}

	if t.udpbaraTunnel != nil {
		t.closeAllProxyConns()
		t.udpbaraTunnel.Close()
	}

	if t.masqueConn != nil {
		t.masqueConn.Close()
	}

	ResetInitialRTT()

	return nil
}

func (t *HTTP3Transport) Refresh() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.dialCount = 0
	t.requestCount = 0

	if t.transport != nil {
		closeWithTimeout(t.transport, 3*time.Second)
	}

	if t.quicTransport != nil && t.udpbaraTunnel == nil && t.masqueConn == nil {
		closeWithTimeout(t.quicTransport, 3*time.Second)
		var localUDPAddr *net.UDPAddr
		if t.localAddr != "" {
			localUDPAddr = &net.UDPAddr{IP: net.ParseIP(t.localAddr)}
		} else {
			localUDPAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}
		udpConn, err := ListenUDPWithLocalAddr("udp", localUDPAddr, t.localAddr)
		if err != nil {
			if t.localAddr != "" {
				return fmt.Errorf("failed to create UDP socket for %s: %w", t.localAddr, err)
			}
			localUDPAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
			udpConn, err = ListenUDPWithLocalAddr("udp6", localUDPAddr, t.localAddr)
			if err != nil {
				return fmt.Errorf("failed to create UDP socket (IPv4 and IPv6 both failed): %w", err)
			}
		}
		t.quicTransport = &quic.Transport{
			Conn:                         udpConn,
			ConnectionIDLength:           t.preset.H3QUICConnectionIDLength(),
			AllowZeroLengthConnectionIDs: true,
		}
	}

	if t.udpbaraTunnel != nil {
		t.closeAllProxyConns()
	}

	additionalSettings := t.buildH3AdditionalSettings()

	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.masqueConn != nil {
		dialFunc = t.dialQUICWithMASQUE
	} else if t.udpbaraTunnel != nil {
		dialFunc = t.dialQUICWithProxy
	} else {
		dialFunc = t.dialQUIC
	}

	t.transport = t.buildHTTP3Transport(dialFunc, additionalSettings)

	return nil
}

func closeWithTimeout(c io.Closer, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func is0RTTRejectedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "0-RTT rejected")
}

func (t *HTTP3Transport) recreateTransport() {
	t.mu.Lock()
	defer t.mu.Unlock()

	additionalSettings := t.buildH3AdditionalSettings()

	var dialFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)
	if t.masqueConn != nil {
		dialFunc = t.dialQUICWithMASQUE
	} else if t.udpbaraTunnel != nil {
		dialFunc = t.dialQUICWithProxy
	} else {
		dialFunc = t.dialQUIC
	}

	t.transport = t.buildHTTP3Transport(dialFunc, additionalSettings)
}

func (t *HTTP3Transport) GetSessionCache() tls.ClientSessionCache {
	return t.sessionCache
}

func (t *HTTP3Transport) SetSessionCache(cache tls.ClientSessionCache) {
	t.sessionCache = cache
	if t.tlsConfig != nil {
		t.tlsConfig.ClientSessionCache = cache
	}
}

func (t *HTTP3Transport) GetECHConfigCache() map[string][]byte {
	t.echConfigCacheMu.RLock()
	defer t.echConfigCacheMu.RUnlock()

	result := make(map[string][]byte, len(t.echConfigCache))
	for k, v := range t.echConfigCache {
		result[k] = v
	}
	return result
}

func (t *HTTP3Transport) SetECHConfigCache(configs map[string][]byte) {
	t.echConfigCacheMu.Lock()
	defer t.echConfigCacheMu.Unlock()

	for k, v := range configs {
		t.echConfigCache[k] = v
	}
}

func (t *HTTP3Transport) Connect(ctx context.Context, host, port string) error {
	connectHost := t.getConnectHost(host)
	addr := net.JoinHostPort(connectHost, port)

	ip, err := t.dnsCache.ResolveOne(ctx, connectHost)
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}

	resolvedAddr := net.JoinHostPort(ip.String(), port)

	var keyLogWriter io.Writer
	if t.config != nil && t.config.KeyLogWriter != nil {
		keyLogWriter = t.config.KeyLogWriter
	} else {
		keyLogWriter = GetKeyLogWriter()
	}

	tlsCfg := &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: t.insecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}

	echConfigList, _ := dns.FetchECHConfigs(ctx, host)

	quicIdleTimeout := 30 * time.Second
	if t.config != nil && t.config.QuicIdleTimeout > 0 {
		quicIdleTimeout = t.config.QuicIdleTimeout
	}

	var clientHelloID *utls.ClientHelloID
	if t.preset.QUICClientHelloID.Client != "" {
		clientHelloID = &t.preset.QUICClientHelloID
	} else if t.preset.ClientHelloID.Client != "" {
		clientHelloID = &t.preset.ClientHelloID
	}

	quicCfg := t.buildQUICConfig(clientHelloID, quicIdleTimeout, 0)
	if len(echConfigList) > 0 {
		quicCfg.ECHConfigList = echConfigList
	}

	conn, err := quic.DialAddr(ctx, resolvedAddr, tlsCfg, quicCfg)
	if err != nil {
		return fmt.Errorf("QUIC dial failed: %w", err)
	}

	t.mu.Lock()
	t.dialCount++
	t.mu.Unlock()

	_ = conn.CloseWithError(0, "connect probe")
	_ = addr // suppress unused warning

	return nil
}

func (t *HTTP3Transport) Stats() HTTP3Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return HTTP3Stats{
		RequestCount: t.requestCount,
		DialCount:    t.dialCount,
		Reusing:      t.requestCount > t.dialCount,
	}
}

type HTTP3Stats struct {
	RequestCount int64
	DialCount    int64 // Number of new connections created
	Reusing      bool  // True if connections are being reused
}

func (t *HTTP3Transport) GetDNSCache() *dns.Cache {
	return t.dnsCache
}

func (t *HTTP3Transport) SetConnectTo(requestHost, connectHost string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	if t.config.ConnectTo == nil {
		t.config.ConnectTo = make(map[string]string)
	}
	t.config.ConnectTo[requestHost] = connectHost
}

func (t *HTTP3Transport) SetECHConfig(echConfig []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfig = echConfig
}

func (t *HTTP3Transport) SetECHConfigDomain(domain string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.config == nil {
		t.config = &TransportConfig{}
	}
	t.config.ECHConfigDomain = domain
}

func (t *HTTP3Transport) getConnectHost(requestHost string) string {
	if t.config == nil || t.config.ConnectTo == nil {
		return requestHost
	}
	if connectHost, ok := t.config.ConnectTo[requestHost]; ok {
		return connectHost
	}
	return requestHost
}

func (t *HTTP3Transport) getECHConfig(ctx context.Context, targetHost string) []byte {
	t.echConfigCacheMu.RLock()
	if cachedConfig, ok := t.echConfigCache[targetHost]; ok {
		t.echConfigCacheMu.RUnlock()
		return cachedConfig
	}
	t.echConfigCacheMu.RUnlock()

	var echConfig []byte
	if t.config == nil {
		echConfig, _ = dns.FetchECHConfigs(ctx, targetHost)
	} else {
		echConfig = t.config.GetECHConfig(ctx, targetHost)
	}

	if echConfig != nil {
		t.echConfigCacheMu.Lock()
		t.echConfigCache[targetHost] = echConfig
		t.echConfigCacheMu.Unlock()
	}

	return echConfig
}
