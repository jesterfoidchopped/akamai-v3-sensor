package dns

import (
	"context"
	"encoding/base64"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Entry struct {
	IPs       []net.IP
	ExpiresAt time.Time
	LookupAt  time.Time
}

func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

type Cache struct {
	entries    map[string]*Entry
	mu         sync.RWMutex
	resolver   *net.Resolver
	defaultTTL time.Duration
	minTTL     time.Duration
	preferIPv4 bool // If true, prefer IPv4 over IPv6
}

func NewCache() *Cache {
	resolver := &net.Resolver{
		PreferGo: false, // Force CGO resolver for shared library compatibility
	}
	return &Cache{
		entries:    make(map[string]*Entry),
		resolver:   resolver,
		defaultTTL: 5 * time.Minute,  // Default TTL if not specified
		minTTL:     30 * time.Second, // Minimum TTL to prevent hammering
		preferIPv4: false,
	}
}

func (c *Cache) SetPreferIPv4(prefer bool) {
	c.mu.Lock()
	c.preferIPv4 = prefer
	c.mu.Unlock()
}

func (c *Cache) PreferIPv4() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.preferIPv4
}

func (c *Cache) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	c.mu.RLock()
	entry, exists := c.entries[host]
	c.mu.RUnlock()

	if exists && !entry.IsExpired() {
		return entry.IPs, nil
	}

	ips, err := c.lookup(ctx, host)
	if err != nil {
		if exists {
			return entry.IPs, nil
		}
		return nil, err
	}

	c.mu.Lock()
	c.entries[host] = &Entry{
		IPs:       ips,
		ExpiresAt: time.Now().Add(c.defaultTTL),
		LookupAt:  time.Now(),
	}
	c.mu.Unlock()

	return ips, nil
}

func (c *Cache) lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	addrs, err := c.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}

	return ips, nil
}

func (c *Cache) ResolveOne(ctx context.Context, host string) (net.IP, error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses found", Name: host}
	}

	if c.PreferIPv4() {
		for _, ip := range ips {
			if ip.To4() != nil {
				return ip, nil
			}
		}
	} else {
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				return ip, nil
			}
		}
	}
	return ips[0], nil
}

func (c *Cache) ResolveAllSorted(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses found", Name: host}
	}

	var ipv4, ipv6 []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}

	result := make([]net.IP, 0, len(ips))
	i, j := 0, 0

	if c.PreferIPv4() {
		for i < len(ipv4) || j < len(ipv6) {
			if i < len(ipv4) {
				result = append(result, ipv4[i])
				i++
			}
			if j < len(ipv6) {
				result = append(result, ipv6[j])
				j++
			}
		}
	} else {
		for i < len(ipv6) || j < len(ipv4) {
			if i < len(ipv6) {
				result = append(result, ipv6[i])
				i++
			}
			if j < len(ipv4) {
				result = append(result, ipv4[j])
				j++
			}
		}
	}

	return result, nil
}

func (c *Cache) ResolveIPv6First(ctx context.Context, host string) (ipv6 []net.IP, ipv4 []net.IP, err error) {
	ips, err := c.Resolve(ctx, host)
	if err != nil {
		return nil, nil, err
	}
	if len(ips) == 0 {
		return nil, nil, &net.DNSError{Err: "no addresses found", Name: host}
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4 = append(ipv4, ip)
		} else {
			ipv6 = append(ipv6, ip)
		}
	}

	return ipv6, ipv4, nil
}

func (c *Cache) Invalidate(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

func (c *Cache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*Entry)
	c.mu.Unlock()
}

func (c *Cache) SetTTL(ttl time.Duration) {
	if ttl < c.minTTL {
		ttl = c.minTTL
	}
	c.defaultTTL = ttl
}

func (c *Cache) Stats() (total int, expired int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now()
	for _, entry := range c.entries {
		total++
		if now.After(entry.ExpiresAt) {
			expired++
		}
	}
	return
}

func (c *Cache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for host, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, host)
		}
	}
}

func (c *Cache) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.Cleanup()
			}
		}
	}()
}

type ECHEntry struct {
	ConfigList []byte
	ExpiresAt  time.Time
}

var (
	echCache   = make(map[string]*ECHEntry)
	echCacheMu sync.RWMutex
)

var (
	echDNSServers   = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	echDNSServersMu sync.RWMutex
)

func SetECHDNSServers(servers []string) {
	echDNSServersMu.Lock()
	defer echDNSServersMu.Unlock()
	if len(servers) == 0 {
		echDNSServers = []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	} else {
		echDNSServers = make([]string, len(servers))
		copy(echDNSServers, servers)
	}
}

func GetECHDNSServers() []string {
	echDNSServersMu.RLock()
	defer echDNSServersMu.RUnlock()
	result := make([]string, len(echDNSServers))
	copy(result, echDNSServers)
	return result
}

func FetchECHConfigs(ctx context.Context, hostname string) ([]byte, error) {
	echCacheMu.RLock()
	entry, exists := echCache[hostname]
	echCacheMu.RUnlock()

	if exists && time.Now().Before(entry.ExpiresAt) {
		return entry.ConfigList, nil
	}

	echConfigList, ttl, err := queryECHFromDNS(ctx, hostname)
	if err != nil {
		if exists {
			return entry.ConfigList, nil
		}
		return nil, nil // No ECH available is not an error
	}

	if echConfigList != nil {
		echCacheMu.Lock()
		echCache[hostname] = &ECHEntry{
			ConfigList: echConfigList,
			ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Second),
		}
		echCacheMu.Unlock()
	}

	return echConfigList, nil
}

func queryECHFromDNS(ctx context.Context, hostname string) ([]byte, uint32, error) {
	client := &dns.Client{
		Timeout: 500 * time.Millisecond, // Short timeout - ECH is optional
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeHTTPS)
	msg.RecursionDesired = true

	dnsServers := GetECHDNSServers()

	var lastErr error
	for _, server := range dnsServers {
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, answer := range resp.Answer {
			if https, ok := answer.(*dns.HTTPS); ok {
				for _, kv := range https.Value {
					if kv.Key() == dns.SVCB_ECHCONFIG {
						echParam, ok := kv.(*dns.SVCBECHConfig)
						if ok && len(echParam.ECH) > 0 {
							return echParam.ECH, https.Hdr.Ttl, nil
						}
					}
				}
			}
		}

		return nil, 300, nil
	}

	return nil, 0, lastErr
}

func FetchECHConfigsBase64(ctx context.Context, hostname string) (string, error) {
	configs, err := FetchECHConfigs(ctx, hostname)
	if err != nil || configs == nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(configs), nil
}
