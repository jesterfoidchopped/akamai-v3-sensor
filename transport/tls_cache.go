package transport

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	tls "github.com/sardanioss/utls"
)

type SessionCacheBackend interface {
	Get(ctx context.Context, key string) (*TLSSessionState, error)

	Put(ctx context.Context, key string, session *TLSSessionState, ttl time.Duration) error

	Delete(ctx context.Context, key string) error

	GetECHConfig(ctx context.Context, key string) ([]byte, error)

	PutECHConfig(ctx context.Context, key string, config []byte, ttl time.Duration) error
}

const (
	CacheKeyPrefixSession = "sensor:sessions"
	CacheKeyPrefixECH     = "sensor:ech"
)

func FormatSessionCacheKey(preset, protocol, host, port string) string {
	return fmt.Sprintf("%s:%s:%s:%s:%s", CacheKeyPrefixSession, preset, protocol, host, port)
}

func FormatSessionCacheKeyWithID(sessionId, preset, protocol, host, port string) string {
	if sessionId == "" {
		return FormatSessionCacheKey(preset, protocol, host, port)
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", CacheKeyPrefixSession, sessionId, preset, protocol, host, port)
}

func FormatECHCacheKey(preset, host, port string) string {
	return fmt.Sprintf("%s:%s:%s:%s", CacheKeyPrefixECH, preset, host, port)
}

const TLSSessionMaxAge = 24 * time.Hour

const TLSSessionCacheMaxSize = 32

type TLSSessionState struct {
	Ticket    string    `json:"ticket"` // base64 encoded
	State     string    `json:"state"`  // base64 encoded
	CreatedAt time.Time `json:"created_at"`
}

func (s *TLSSessionState) ToClientSessionState() (*tls.ClientSessionState, error) {
	ticket, err := base64.StdEncoding.DecodeString(s.Ticket)
	if err != nil {
		return nil, fmt.Errorf("decode ticket: %w", err)
	}

	stateBytes, err := base64.StdEncoding.DecodeString(s.State)
	if err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}

	state, err := tls.ParseSessionState(stateBytes)
	if err != nil {
		return nil, fmt.Errorf("parse session state: %w", err)
	}

	clientState, err := tls.NewResumptionState(ticket, state)
	if err != nil {
		return nil, fmt.Errorf("create resumption state: %w", err)
	}

	return clientState, nil
}

func NewTLSSessionState(cs *tls.ClientSessionState) (*TLSSessionState, error) {
	if cs == nil {
		return nil, fmt.Errorf("client session state is nil")
	}

	ticket, state, err := cs.ResumptionState()
	if err != nil {
		return nil, fmt.Errorf("get resumption state: %w", err)
	}

	if state == nil || ticket == nil {
		return nil, fmt.Errorf("invalid session state")
	}

	stateBytes, err := state.Bytes()
	if err != nil {
		return nil, fmt.Errorf("serialize session state: %w", err)
	}

	return &TLSSessionState{
		Ticket:    base64.StdEncoding.EncodeToString(ticket),
		State:     base64.StdEncoding.EncodeToString(stateBytes),
		CreatedAt: time.Now(),
	}, nil
}

type ErrorCallback func(operation string, key string, err error)

type PersistableSessionCache struct {
	mu          sync.RWMutex
	sessions    map[string]*cachedSession
	accessOrder []string // LRU order: oldest at front, newest at back

	backend       SessionCacheBackend
	preset        string                        // Preset name for cache key generation
	protocol      string                        // Protocol identifier (h1, h2, h3)
	sessionId     string                        // Optional session identifier for cache key isolation
	errorCallback atomic.Pointer[ErrorCallback] // Optional callback for backend errors (lock-free)
}

type cachedSession struct {
	state     *tls.ClientSessionState
	createdAt time.Time
}

func NewPersistableSessionCache() *PersistableSessionCache {
	return &PersistableSessionCache{
		sessions: make(map[string]*cachedSession),
	}
}

func NewPersistableSessionCacheWithBackend(backend SessionCacheBackend, preset, protocol string, errorCallback ErrorCallback) *PersistableSessionCache {
	cache := &PersistableSessionCache{
		sessions: make(map[string]*cachedSession),
		backend:  backend,
		preset:   preset,
		protocol: protocol,
	}
	if errorCallback != nil {
		cache.errorCallback.Store(&errorCallback)
	}
	return cache
}

func (c *PersistableSessionCache) SetBackend(backend SessionCacheBackend, preset, protocol string, errorCallback ErrorCallback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backend = backend
	c.preset = preset
	c.protocol = protocol
	if errorCallback != nil {
		c.errorCallback.Store(&errorCallback)
	} else {
		c.errorCallback.Store(nil)
	}
}

func (c *PersistableSessionCache) SetSessionIdentifier(sessionId string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionId = sessionId
}

func (c *PersistableSessionCache) GetSessionIdentifier() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionId
}

func (c *PersistableSessionCache) SetErrorCallback(callback ErrorCallback) {
	if callback != nil {
		c.errorCallback.Store(&callback)
	} else {
		c.errorCallback.Store(nil)
	}
}

func (c *PersistableSessionCache) reportError(operation, key string, err error) {
	if err == nil {
		return
	}
	if cb := c.errorCallback.Load(); cb != nil {
		(*cb)(operation, key, err)
	}
}

func (c *PersistableSessionCache) Get(sessionKey string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if cached, ok := c.sessions[sessionKey]; ok {
		c.moveToEnd(sessionKey)
		return cached.state, true
	}

	if c.backend != nil {
		state, err := c.getFromBackend(sessionKey)
		if err != nil {
			c.reportError("get", sessionKey, err)
		}
		if state != nil {
			return state, true
		}
	}

	return nil, false
}

func (c *PersistableSessionCache) getFromBackend(sessionKey string) (*tls.ClientSessionState, error) {
	host, port := parseSessionKey(sessionKey)
	if host == "" {
		return nil, nil
	}

	backendKey := FormatSessionCacheKeyWithID(c.sessionId, c.preset, c.protocol, host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sessionState, err := c.backend.Get(ctx, backendKey)
	if err != nil {
		return nil, err
	}
	if sessionState == nil {
		return nil, nil
	}

	if time.Since(sessionState.CreatedAt) > TLSSessionMaxAge {
		return nil, nil
	}

	clientState, err := sessionState.ToClientSessionState()
	if err != nil {
		return nil, err
	}

	c.sessions[sessionKey] = &cachedSession{
		state:     clientState,
		createdAt: sessionState.CreatedAt,
	}
	c.accessOrder = append(c.accessOrder, sessionKey)

	c.evictIfNeeded()

	return clientState, nil
}

func parseSessionKey(key string) (host, port string) {
	if idx := len("https://"); len(key) > idx && key[:idx] == "https://" {
		key = key[idx:]
	} else if idx := len("http://"); len(key) > idx && key[:idx] == "http://" {
		key = key[idx:]
	}

	lastColon := -1
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == ':' {
			lastColon = i
			break
		}
	}

	if lastColon == -1 {
		return key, "443" // Default to HTTPS port
	}

	return key[:lastColon], key[lastColon+1:]
}

func (c *PersistableSessionCache) evictIfNeeded() {
	for len(c.sessions) > TLSSessionCacheMaxSize && len(c.accessOrder) > 0 {
		oldest := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]
		delete(c.sessions, oldest)
	}
}

func (c *PersistableSessionCache) moveToEnd(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			c.accessOrder = append(c.accessOrder, key)
			return
		}
	}
}

func (c *PersistableSessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	if _, exists := c.sessions[sessionKey]; exists {
		c.sessions[sessionKey] = &cachedSession{
			state:     cs,
			createdAt: now,
		}
		c.moveToEnd(sessionKey)
	} else {
		c.evictIfNeeded()

		c.sessions[sessionKey] = &cachedSession{
			state:     cs,
			createdAt: now,
		}
		c.accessOrder = append(c.accessOrder, sessionKey)
	}

	if c.backend != nil {
		go c.putToBackend(sessionKey, cs)
	}
}

func (c *PersistableSessionCache) putToBackend(sessionKey string, cs *tls.ClientSessionState) {
	host, port := parseSessionKey(sessionKey)
	if host == "" {
		return
	}

	sessionState, err := NewTLSSessionState(cs)
	if err != nil {
		c.reportError("put_serialize", sessionKey, err)
		return
	}

	backendKey := FormatSessionCacheKeyWithID(c.sessionId, c.preset, c.protocol, host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := c.backend.Put(ctx, backendKey, sessionState, TLSSessionMaxAge); err != nil {
		c.reportError("put", backendKey, err)
	}
}

func (c *PersistableSessionCache) Export() (map[string]TLSSessionState, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]TLSSessionState)

	for key, cached := range c.sessions {
		if cached.state == nil {
			continue
		}

		ticket, state, err := cached.state.ResumptionState()
		if err != nil {
			continue // Skip invalid sessions
		}

		if state == nil || ticket == nil {
			continue
		}

		stateBytes, err := state.Bytes()
		if err != nil {
			continue // Skip sessions that can't be serialized
		}

		result[key] = TLSSessionState{
			Ticket:    base64.StdEncoding.EncodeToString(ticket),
			State:     base64.StdEncoding.EncodeToString(stateBytes),
			CreatedAt: cached.createdAt,
		}
	}

	return result, nil
}

func (c *PersistableSessionCache) Import(sessions map[string]TLSSessionState) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, serialized := range sessions {
		if time.Since(serialized.CreatedAt) > TLSSessionMaxAge {
			continue
		}

		ticket, err := base64.StdEncoding.DecodeString(serialized.Ticket)
		if err != nil {
			continue
		}

		stateBytes, err := base64.StdEncoding.DecodeString(serialized.State)
		if err != nil {
			continue
		}

		state, err := tls.ParseSessionState(stateBytes)
		if err != nil {
			continue
		}

		clientState, err := tls.NewResumptionState(ticket, state)
		if err != nil {
			continue
		}

		c.sessions[key] = &cachedSession{
			state:     clientState,
			createdAt: serialized.CreatedAt,
		}
		c.accessOrder = append(c.accessOrder, key)
	}

	for len(c.sessions) > TLSSessionCacheMaxSize && len(c.accessOrder) > 0 {
		oldest := c.accessOrder[0]
		c.accessOrder = c.accessOrder[1:]
		delete(c.sessions, oldest)
	}

	return nil
}

func (c *PersistableSessionCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessions = make(map[string]*cachedSession)
	c.accessOrder = nil
}

func (c *PersistableSessionCache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.sessions)
}
