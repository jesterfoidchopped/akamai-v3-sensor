package pool

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"io"

	"github.com/jesterfoidchopped/akamai-v3-sensor/dns"
	"github.com/jesterfoidchopped/akamai-v3-sensor/fingerprint"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
	"github.com/sardanioss/quic-go"
	"github.com/sardanioss/quic-go/http3"
	tls "github.com/sardanioss/utls"
	utls "github.com/sardanioss/utls"
)

const (
	settingQPACKMaxTableCapacity = 0x1
	settingMaxFieldSectionSize   = 0x6
	settingQPACKBlockedStreams   = 0x7
	settingH3Datagram            = 0x33
)

type QUICConn struct {
	Host       string
	RemoteAddr net.Addr
	QUICConn   *quic.Conn
	HTTP3RT    *http3.Transport
	CreatedAt  time.Time
	LastUsedAt time.Time
	UseCount   int64
	mu         sync.Mutex
	closed     bool
}

func (c *QUICConn) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	if c.QUICConn != nil {
		select {
		case <-c.QUICConn.Context().Done():
			return false
		default:
			return true
		}
	}

	if c.HTTP3RT != nil {
		return true
	}

	return false
}

func (c *QUICConn) Age() time.Duration {
	return time.Since(c.CreatedAt)
}

func (c *QUICConn) IdleTime() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.LastUsedAt)
}

func (c *QUICConn) MarkUsed() {
	c.mu.Lock()
	c.LastUsedAt = time.Now()
	c.UseCount++
	c.mu.Unlock()
}

func (c *QUICConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	var errs []error
	if c.HTTP3RT != nil {
		if err := c.HTTP3RT.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.QUICConn != nil {
		if err := c.QUICConn.CloseWithError(quic.ApplicationErrorCode(0), "closing"); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

type QUICHostPool struct {
	host        string // Connection host (for DNS resolution - may be connectTo target)
	sniHost     string // SNI host (for TLS ServerName - always the original request host)
	port        string
	preset      *fingerprint.Preset
	dnsCache    *dns.Cache
	connections []*QUICConn
	mu          sync.Mutex

	cachedClientHelloSpec *utls.ClientHelloSpec

	cachedPSKSpec *utls.ClientHelloSpec

	shuffleSeed int64

	sessionCache tls.ClientSessionCache

	maxConns           int
	maxIdleTime        time.Duration
	maxConnAge         time.Duration
	connectTimeout     time.Duration
	echConfig          []byte // Custom ECH configuration
	echConfigDomain    string // Domain to fetch ECH config from
	disableECH         bool   // Disable automatic ECH fetching (Chrome doesn't always use ECH)
	insecureSkipVerify bool   // Skip TLS certificate verification (for testing)
	localAddr          string // Local IP to bind outgoing connections
}

func NewQUICHostPool(host, port string, preset *fingerprint.Preset, dnsCache *dns.Cache) *QUICHostPool {
	var cachedSpec *utls.ClientHelloSpec
	var cachedPSKSpec *utls.ClientHelloSpec
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	if preset != nil && preset.QUICClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICClientHelloID, shuffleSeed); err == nil {
			cachedSpec = &spec
		}
	}
	if preset != nil && preset.QUICPSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			cachedPSKSpec = &spec
		}
	}
	return NewQUICHostPoolWithCachedSpec(host, "", port, preset, dnsCache, cachedSpec, cachedPSKSpec, shuffleSeed)
}

func NewQUICHostPoolWithCachedSpec(host, sniHost, port string, preset *fingerprint.Preset, dnsCache *dns.Cache, cachedSpec *utls.ClientHelloSpec, cachedPSKSpec *utls.ClientHelloSpec, shuffleSeed int64) *QUICHostPool {
	if sniHost == "" {
		sniHost = host
	}
	pool := &QUICHostPool{
		host:                  host,
		sniHost:               sniHost,
		port:                  port,
		preset:                preset,
		dnsCache:              dnsCache,
		connections:           make([]*QUICConn, 0),
		maxConns:              0, // 0 = unlimited
		maxIdleTime:           90 * time.Second,
		maxConnAge:            5 * time.Minute,
		connectTimeout:        30 * time.Second,
		cachedClientHelloSpec: cachedSpec,                       // Use manager's cached spec for consistent TLS shuffle
		cachedPSKSpec:         cachedPSKSpec,                    // PSK spec for session resumption
		shuffleSeed:           shuffleSeed,                      // Use manager's seed for consistent transport param shuffle
		sessionCache:          tls.NewLRUClientSessionCache(32), // Session cache for 0-RTT resumption
	}

	return pool
}

func (p *QUICHostPool) SetMaxConns(max int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxConns = max
}

func (p *QUICHostPool) SetLocalAddr(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.localAddr = addr
}

func (p *QUICHostPool) GetConn(ctx context.Context) (*QUICConn, error) {
	p.mu.Lock()

	for i, conn := range p.connections {
		if conn.IsHealthy() && conn.IdleTime() < p.maxIdleTime && conn.Age() < p.maxConnAge {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			p.connections = append(p.connections, conn)
			p.mu.Unlock()
			conn.MarkUsed()
			return conn, nil
		}
	}

	healthy := make([]*QUICConn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IsHealthy() && conn.Age() < p.maxConnAge {
			healthy = append(healthy, conn)
		} else {
			go conn.Close()
		}
	}
	p.connections = healthy

	if p.maxConns > 0 && len(p.connections) >= p.maxConns {
		p.mu.Unlock()
		return nil, ErrNoConnections
	}

	p.mu.Unlock()

	conn, err := p.createConn(ctx)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.connections = append(p.connections, conn)
	p.mu.Unlock()

	return conn, nil
}

func (p *QUICHostPool) createConn(ctx context.Context) (*QUICConn, error) {
	var keyLogWriter io.Writer = transport.GetKeyLogWriter()

	tlsConfig := &tls.Config{
		ServerName:         p.sniHost,
		InsecureSkipVerify: p.insecureSkipVerify,
		NextProtos:         []string{http3.NextProtoH3}, // HTTP/3 ALPN
		MinVersion:         tls.VersionTLS13,
		KeyLogWriter:       keyLogWriter,
	}

	if p.cachedPSKSpec != nil {
		tlsConfig.ClientSessionCache = p.sessionCache
	}

	var selectedSpec *utls.ClientHelloSpec
	var clientHelloID *utls.ClientHelloID

	hasSession := p.hasSessionForHost()

	if hasSession && p.cachedPSKSpec != nil && p.preset != nil && p.preset.QUICPSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(p.preset.QUICPSKClientHelloID, p.shuffleSeed); err == nil {
			selectedSpec = &spec
		}
		clientHelloID = &p.preset.QUICPSKClientHelloID
	}
	if selectedSpec == nil && p.cachedClientHelloSpec != nil && p.preset != nil && p.preset.QUICClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(p.preset.QUICClientHelloID, p.shuffleSeed); err == nil {
			selectedSpec = &spec
		}
		clientHelloID = &p.preset.QUICClientHelloID
	}

	var echConfigList []byte
	if !p.disableECH {
		if len(p.echConfig) > 0 {
			echConfigList = p.echConfig
		} else if p.echConfigDomain != "" {
			echConfigList, _ = dns.FetchECHConfigs(ctx, p.echConfigDomain)
		} else if clientHelloID != nil {
			echConfigList, _ = dns.FetchECHConfigs(ctx, p.sniHost)
		}
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:                30 * time.Second, // Chrome uses 30s
		KeepAlivePeriod:               15 * time.Second, // Send keepalives before idle timeout
		MaxIncomingStreams:            p.preset.H3QUICMaxIncomingStreams(),
		MaxIncomingUniStreams:         p.preset.H3QUICMaxIncomingUniStreams(),
		Allow0RTT:                     p.preset.H3QUICAllow0RTT(),
		EnableDatagrams:               true, // Always true at QUIC level (original behavior); H3 SETTINGS controls per-browser advertisement
		InitialPacketSize:             p.preset.H3QUICInitialPacketSize(),
		DisableClientHelloScrambling:  p.preset.H3QUICDisableHelloScramble(),
		ChromeStyleInitialPackets:     p.preset.H3QUICChromeStyleInitial(),
		ClientHelloID:                 clientHelloID,
		CachedClientHelloSpec:         selectedSpec,
		TransportParameterOrder:       resolveTransportParamOrder(p.preset.H3QUICTransportParamOrder()),
		TransportParameterShuffleSeed: p.shuffleSeed,
		MaxDatagramFrameSize:          p.preset.H3QUICMaxDatagramFrameSize(),
	}
	if len(echConfigList) > 0 {
		quicConfig.ECHConfigList = echConfigList
	}

	ipv6, ipv4, err := p.dnsCache.ResolveIPv6First(ctx, p.host)
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed: %w", err)
	}

	preferIPv4 := p.dnsCache != nil && p.dnsCache.PreferIPv4()

	port, _ := net.LookupPort("udp", p.port)
	if port == 0 {
		port = 443
	}

	var rttHost string
	if len(ipv6) > 0 {
		rttHost = ipv6[0].String()
	} else if len(ipv4) > 0 {
		rttHost = ipv4[0].String()
	}
	quicConfig.AdditionalTransportParameters = transport.AdditionalTransportParamsForPreset(p.preset, ctx, rttHost, port)

	greaseSettingN := uint64(1000000000 + rand.Int63n(9000000000))
	greaseSettingID := 0x1f*greaseSettingN + 0x21
	greaseSettingValue := uint64(1 + rand.Uint32()%(1<<32-1))

	additionalSettings := map[uint64]uint64{
		settingQPACKMaxTableCapacity: p.preset.H3QPACKMaxTableCapacity(),
		settingQPACKBlockedStreams:   p.preset.H3QPACKBlockedStreams(),
		greaseSettingID:              greaseSettingValue,
	}

	if maxField := p.preset.H3MaxFieldSectionSize(); maxField > 0 {
		additionalSettings[settingMaxFieldSectionSize] = maxField
	}
	if p.preset.H3EnableDatagrams() {
		additionalSettings[settingH3Datagram] = 1
	}

	var preferredIPs, fallbackIPs []net.IP
	if preferIPv4 {
		preferredIPs = ipv4
		fallbackIPs = ipv6
	} else {
		preferredIPs = ipv6
		fallbackIPs = ipv4
	}

	localAddr := p.localAddr

	h3Transport := &http3.Transport{
		TLSClientConfig:        tlsConfig,
		QUICConfig:             quicConfig,
		EnableDatagrams:        true, // Always true at HTTP/3 level (original behavior); H3 SETTINGS controls per-browser advertisement
		AdditionalSettings:     additionalSettings,
		MaxResponseHeaderBytes: int(p.preset.H3MaxResponseHeaderBytes()),
		SendGreaseFrames:       p.preset.H3SendGreaseFrames(),
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			allIPs := append(preferredIPs, fallbackIPs...)
			if len(allIPs) == 0 {
				return nil, fmt.Errorf("no IP addresses available for %s", addr)
			}

			var lastErr error
			for _, remoteIP := range allIPs {
				network := "udp4"
				if remoteIP.To4() == nil {
					network = "udp6"
				}
				udpAddr := &net.UDPAddr{IP: remoteIP, Port: port}

				var localUDPAddr *net.UDPAddr
				if localAddr != "" {
					localUDPAddr = &net.UDPAddr{IP: net.ParseIP(localAddr)}
				}

				udpConn, err := net.ListenUDP(network, localUDPAddr)
				if err != nil {
					lastErr = err
					continue
				}

				quicTransport := &quic.Transport{
					Conn:                         udpConn,
					ConnectionIDLength:           p.preset.H3QUICConnectionIDLength(),
					AllowZeroLengthConnectionIDs: true,
				}

				conn, err := quicTransport.DialEarly(ctx, udpAddr, tlsCfg, cfg)
				if err != nil {
					quicTransport.Close()
					lastErr = err
					continue
				}

				return conn, nil
			}

			if lastErr != nil {
				return nil, lastErr
			}
			return nil, fmt.Errorf("all QUIC connection attempts failed for %s", addr)
		},
	}

	conn := &QUICConn{
		Host:       p.host,
		RemoteAddr: nil,
		QUICConn:   nil,
		HTTP3RT:    h3Transport,
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
		UseCount:   0,
	}

	return conn, nil
}

func (p *QUICHostPool) CloseIdle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	active := make([]*QUICConn, 0, len(p.connections))
	for _, conn := range p.connections {
		if conn.IdleTime() > p.maxIdleTime || conn.Age() > p.maxConnAge || !conn.IsHealthy() {
			go conn.Close()
		} else {
			active = append(active, conn)
		}
	}
	p.connections = active
}

func (p *QUICHostPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = nil
}

func (p *QUICHostPool) CloseConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		go conn.Close()
	}
	p.connections = make([]*QUICConn, 0)
}

func (p *QUICHostPool) hasSessionForHost() bool {
	if p.sessionCache == nil {
		return false
	}
	session, ok := p.sessionCache.Get(p.sniHost)
	return ok && session != nil
}

func (p *QUICHostPool) Stats() (total int, healthy int, totalRequests int64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		total++
		if conn.IsHealthy() {
			healthy++
		}
		totalRequests += conn.UseCount
	}
	return
}

type QUICManager struct {
	pools    map[string]*QUICHostPool
	mu       sync.RWMutex
	dnsCache *dns.Cache
	preset   *fingerprint.Preset
	closed   bool

	maxConnsPerHost    int               // 0 = unlimited
	connectTo          map[string]string // Domain fronting: request host -> connect host
	echConfig          []byte            // Custom ECH configuration
	echConfigDomain    string            // Domain to fetch ECH config from
	disableECH         bool              // Disable automatic ECH fetching
	insecureSkipVerify bool              // Skip TLS certificate verification
	localAddr          string            // Local IP to bind outgoing connections

	cachedSpec    *utls.ClientHelloSpec
	cachedPSKSpec *utls.ClientHelloSpec
	shuffleSeed   int64 // Seed used for extension shuffling

	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

func NewQUICManager(preset *fingerprint.Preset, dnsCache *dns.Cache) *QUICManager {
	var seedBytes [8]byte
	crand.Read(seedBytes[:])
	shuffleSeed := int64(binary.LittleEndian.Uint64(seedBytes[:]))

	m := &QUICManager{
		pools:           make(map[string]*QUICHostPool),
		dnsCache:        dnsCache,
		preset:          preset,
		maxConnsPerHost: 0, // 0 = unlimited by default
		shuffleSeed:     shuffleSeed,
		cleanupInterval: 30 * time.Second,
		stopCleanup:     make(chan struct{}),
	}

	if preset != nil && preset.QUICClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICClientHelloID, shuffleSeed); err == nil {
			m.cachedSpec = &spec
		}
	}

	if preset != nil && preset.QUICPSKClientHelloID.Client != "" {
		if spec, err := utls.UTLSIdToSpecWithSeed(preset.QUICPSKClientHelloID, shuffleSeed); err == nil {
			m.cachedPSKSpec = &spec
		}
	}

	go m.cleanupLoop()

	return m
}

func (m *QUICManager) SetMaxConnsPerHost(max int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.maxConnsPerHost = max
}

func (m *QUICManager) SetConnectTo(requestHost, connectHost string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.connectTo == nil {
		m.connectTo = make(map[string]string)
	}
	m.connectTo[requestHost] = connectHost
}

func (m *QUICManager) SetECHConfig(echConfig []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfig = echConfig
}

func (m *QUICManager) SetECHConfigDomain(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.echConfigDomain = domain
}

func (m *QUICManager) SetDisableECH(disable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disableECH = disable
}

func (m *QUICManager) SetInsecureSkipVerify(skip bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.insecureSkipVerify = skip
}

func (m *QUICManager) SetLocalAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localAddr = addr
}

func (m *QUICManager) GetPool(host, port string) (*QUICHostPool, error) {
	if port == "" {
		port = "443"
	}

	connectHost := host
	if m.connectTo != nil {
		if mapped, ok := m.connectTo[host]; ok {
			connectHost = mapped
		}
	}
	key := net.JoinHostPort(connectHost, port)

	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return nil, ErrPoolClosed
	}
	pool, exists := m.pools[key]
	m.mu.RUnlock()

	if exists {
		return pool, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, ErrPoolClosed
	}

	if pool, exists = m.pools[key]; exists {
		return pool, nil
	}

	sniHost := ""
	if connectHost != host {
		sniHost = host // Original request host for TLS ServerName
	}
	pool = NewQUICHostPoolWithCachedSpec(connectHost, sniHost, port, m.preset, m.dnsCache, m.cachedSpec, m.cachedPSKSpec, m.shuffleSeed)
	if m.maxConnsPerHost > 0 {
		pool.SetMaxConns(m.maxConnsPerHost)
	}
	if len(m.echConfig) > 0 {
		pool.echConfig = m.echConfig
	}
	if m.echConfigDomain != "" {
		pool.echConfigDomain = m.echConfigDomain
	}
	pool.disableECH = m.disableECH
	pool.insecureSkipVerify = m.insecureSkipVerify
	if m.localAddr != "" {
		pool.localAddr = m.localAddr
	}
	m.pools[key] = pool
	return pool, nil
}

func (m *QUICManager) GetConn(ctx context.Context, host, port string) (*QUICConn, error) {
	pool, err := m.GetPool(host, port)
	if err != nil {
		return nil, err
	}
	return pool.GetConn(ctx)
}

func (m *QUICManager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *QUICManager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, pool := range m.pools {
		pool.CloseIdle()
		total, _, _ := pool.Stats()
		if total == 0 {
			delete(m.pools, key)
		}
	}
}

func (m *QUICManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}
	m.closed = true

	close(m.stopCleanup)

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = nil
}

func (m *QUICManager) CloseAllConnections() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.pools {
		pool.CloseConnections()
	}
}

func (m *QUICManager) CloseAllPools() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, pool := range m.pools {
		pool.Close()
	}
	m.pools = make(map[string]*QUICHostPool)
}

func (m *QUICManager) Stats() map[string]struct {
	Total    int
	Healthy  int
	Requests int64
} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]struct {
		Total    int
		Healthy  int
		Requests int64
	})

	for key, pool := range m.pools {
		t, h, r := pool.Stats()
		stats[key] = struct {
			Total    int
			Healthy  int
			Requests int64
		}{t, h, r}
	}

	return stats
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
