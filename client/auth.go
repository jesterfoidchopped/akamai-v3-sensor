package client

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	http "github.com/sardanioss/http"
	"strings"
)

type Auth interface {
	Apply(req *http.Request) error
	HandleChallenge(resp *http.Response, req *http.Request) (bool, error)
}

type BasicAuth struct {
	Username string
	Password string
}

func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		Username: username,
		Password: password,
	}
}

func (a *BasicAuth) Apply(req *http.Request) error {
	auth := a.Username + ":" + a.Password
	encoded := base64.StdEncoding.EncodeToString([]byte(auth))
	req.Header.Set("Authorization", "Basic "+encoded)
	return nil
}

func (a *BasicAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
	return false, nil
}

type DigestAuth struct {
	Username string
	Password string

	realm     string
	nonce     string
	qop       string
	opaque    string
	algorithm string
	nc        int
}

func NewDigestAuth(username, password string) *DigestAuth {
	return &DigestAuth{
		Username: username,
		Password: password,
		nc:       0,
	}
}

func (a *DigestAuth) Apply(req *http.Request) error {
	if a.nonce == "" {
		return nil
	}
	return a.applyDigestHeader(req)
}

func (a *DigestAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
	if resp.StatusCode != http.StatusUnauthorized {
		return false, nil
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" || !strings.HasPrefix(strings.ToLower(wwwAuth), "digest ") {
		return false, nil
	}

	if err := a.parseChallenge(wwwAuth); err != nil {
		return false, err
	}

	return true, nil
}

func (a *DigestAuth) parseChallenge(wwwAuth string) error {
	params := strings.TrimPrefix(wwwAuth, "Digest ")
	params = strings.TrimPrefix(params, "digest ")

	for _, part := range strings.Split(params, ",") {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		value := strings.TrimSpace(part[idx+1:])
		value = strings.Trim(value, `"`)

		switch key {
		case "realm":
			a.realm = value
		case "nonce":
			a.nonce = value
		case "qop":
			a.qop = value
		case "opaque":
			a.opaque = value
		case "algorithm":
			a.algorithm = value
		}
	}

	if a.nonce == "" {
		return fmt.Errorf("digest auth: missing nonce in challenge")
	}

	return nil
}

func (a *DigestAuth) applyDigestHeader(req *http.Request) error {
	a.nc++
	nc := fmt.Sprintf("%08x", a.nc)

	cnonce := generateCnonce()

	uri := req.URL.RequestURI()
	method := req.Method
	if method == "" {
		method = "GET"
	}

	ha1 := md5Hash(fmt.Sprintf("%s:%s:%s", a.Username, a.realm, a.Password))

	ha2 := md5Hash(fmt.Sprintf("%s:%s", method, uri))

	var response string
	if a.qop == "auth" || a.qop == "auth-int" {
		response = md5Hash(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, a.nonce, nc, cnonce, a.qop, ha2))
	} else {
		response = md5Hash(fmt.Sprintf("%s:%s:%s", ha1, a.nonce, ha2))
	}

	auth := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		a.Username, a.realm, a.nonce, uri, response)

	if a.qop != "" {
		auth += fmt.Sprintf(`, qop=%s, nc=%s, cnonce="%s"`, a.qop, nc, cnonce)
	}

	if a.opaque != "" {
		auth += fmt.Sprintf(`, opaque="%s"`, a.opaque)
	}

	if a.algorithm != "" {
		auth += fmt.Sprintf(`, algorithm=%s`, a.algorithm)
	}

	req.Header.Set("Authorization", auth)
	return nil
}

func md5Hash(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

func generateCnonce() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type BearerAuth struct {
	Token string
}

func NewBearerAuth(token string) *BearerAuth {
	return &BearerAuth{Token: token}
}

func (a *BearerAuth) Apply(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer "+a.Token)
	return nil
}

func (a *BearerAuth) HandleChallenge(resp *http.Response, req *http.Request) (bool, error) {
	return false, nil
}
