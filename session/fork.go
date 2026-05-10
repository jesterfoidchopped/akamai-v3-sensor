package session

import (
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
)

func (s *Session) Fork(n int) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.active || n <= 0 {
		return nil
	}

	forks := make([]*Session, n)
	for i := range forks {
		forks[i] = s.forkOne()
	}
	return forks
}

func (s *Session) forkOne() *Session {
	cfgCopy := *s.Config

	presetName := "chrome-latest"
	if cfgCopy.Preset != "" {
		presetName = cfgCopy.Preset
	}

	var proxy *transport.ProxyConfig
	if cfgCopy.Proxy != "" || cfgCopy.TCPProxy != "" || cfgCopy.UDPProxy != "" {
		proxy = &transport.ProxyConfig{
			URL:      cfgCopy.Proxy,
			TCPProxy: cfgCopy.TCPProxy,
			UDPProxy: cfgCopy.UDPProxy,
		}
	}

	var transportConfig *transport.TransportConfig
	if parentConfig := s.transport.GetConfig(); parentConfig != nil {
		cfgCopy := *parentConfig
		cfgCopy.KeyLogWriter = nil
		transportConfig = &cfgCopy
	} else {
		needsConfig := len(cfgCopy.ConnectTo) > 0 || cfgCopy.ECHConfigDomain != "" ||
			cfgCopy.TLSOnly || cfgCopy.QuicIdleTimeout > 0 || cfgCopy.LocalAddress != "" ||
			cfgCopy.EnableSpeculativeTLS
		if needsConfig {
			transportConfig = &transport.TransportConfig{
				ConnectTo:            cfgCopy.ConnectTo,
				ECHConfigDomain:      cfgCopy.ECHConfigDomain,
				TLSOnly:              cfgCopy.TLSOnly,
				QuicIdleTimeout:      time.Duration(cfgCopy.QuicIdleTimeout) * time.Second,
				LocalAddr:            cfgCopy.LocalAddress,
				EnableSpeculativeTLS: cfgCopy.EnableSpeculativeTLS,
			}
		}
	}

	t := transport.NewTransportWithConfig(presetName, proxy, transportConfig)

	if cfgCopy.InsecureSkipVerify {
		t.SetInsecureSkipVerify(true)
	}
	if cfgCopy.ForceHTTP1 {
		t.SetProtocol(transport.ProtocolHTTP1)
	} else if cfgCopy.ForceHTTP2 {
		t.SetProtocol(transport.ProtocolHTTP2)
	} else if cfgCopy.ForceHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP3)
	} else if cfgCopy.DisableHTTP3 {
		t.SetProtocol(transport.ProtocolHTTP2)
	}

	if cfgCopy.PreferIPv4 {
		if dnsCache := t.GetDNSCache(); dnsCache != nil {
			dnsCache.SetPreferIPv4(true)
		}
	}

	if cfgCopy.DisableECH {
		t.SetDisableECH(true)
	}

	if parentH1 := s.transport.GetHTTP1Transport(); parentH1 != nil {
		if forkH1 := t.GetHTTP1Transport(); forkH1 != nil {
			forkH1.SetSessionCache(parentH1.GetSessionCache())
		}
	}
	if parentH2 := s.transport.GetHTTP2Transport(); parentH2 != nil {
		if forkH2 := t.GetHTTP2Transport(); forkH2 != nil {
			forkH2.SetSessionCache(parentH2.GetSessionCache())
		}
	}
	if parentH3 := s.transport.GetHTTP3Transport(); parentH3 != nil {
		if forkH3 := t.GetHTTP3Transport(); forkH3 != nil {
			forkH3.SetSessionCache(parentH3.GetSessionCache())
		}
	}

	cacheEntries := make(map[string]*cacheEntry, len(s.cacheEntries))
	for k, v := range s.cacheEntries {
		entryCopy := *v
		cacheEntries[k] = &entryCopy
	}

	clientHints := make(map[string]map[string]bool, len(s.clientHints))
	for host, hints := range s.clientHints {
		hintsCopy := make(map[string]bool, len(hints))
		for k, v := range hints {
			hintsCopy[k] = v
		}
		clientHints[host] = hintsCopy
	}

	switchProto := transport.ProtocolAuto
	if cfgCopy.SwitchProtocol != "" {
		p, err := parseProtocol(cfgCopy.SwitchProtocol)
		if err == nil {
			switchProto = p
		}
	}

	return &Session{
		ID:             generateID(),
		CreatedAt:      time.Now(),
		LastUsed:       time.Now(),
		RequestCount:   0,
		Config:         &cfgCopy,
		transport:      t,
		cookies:        s.cookies, // shared pointer — thread-safe CookieJar
		cacheEntries:   cacheEntries,
		clientHints:    clientHints,
		keyLogWriter:   nil, // no key log on fork to avoid double-close
		switchProtocol: switchProto,
		active:         true,
	}
}
