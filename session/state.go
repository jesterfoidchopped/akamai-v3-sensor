package session

import (
	"time"

	"github.com/jesterfoidchopped/akamai-v3-sensor/protocol"
	"github.com/jesterfoidchopped/akamai-v3-sensor/transport"
)

const SessionStateVersion = 5

type SessionState struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	Config *protocol.SessionConfig `json:"config"`

	Cookies map[string][]CookieState `json:"cookies"`

	TLSSessions map[string]transport.TLSSessionState `json:"tls_sessions"`

	ECHConfigs map[string]string `json:"ech_configs,omitempty"`
}

type SessionStateV4 struct {
	Version     int                                  `json:"version"`
	CreatedAt   time.Time                            `json:"created_at"`
	UpdatedAt   time.Time                            `json:"updated_at"`
	Config      *protocol.SessionConfig              `json:"config"`
	Cookies     []CookieState                        `json:"cookies"` // v4: flat list
	TLSSessions map[string]transport.TLSSessionState `json:"tls_sessions"`
	ECHConfigs  map[string]string                    `json:"ech_configs,omitempty"`
}

type CookieState struct {
	Name      string     `json:"name"`
	Value     string     `json:"value"`
	Domain    string     `json:"domain,omitempty"`
	Path      string     `json:"path,omitempty"`
	Expires   *time.Time `json:"expires,omitempty"`
	MaxAge    int        `json:"max_age,omitempty"`
	Secure    bool       `json:"secure,omitempty"`
	HttpOnly  bool       `json:"http_only,omitempty"`
	SameSite  string     `json:"same_site,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"` // v5: for sorting
}
