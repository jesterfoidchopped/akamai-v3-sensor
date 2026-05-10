package session

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type CookieJar struct {
	mu      sync.RWMutex
	cookies map[string]map[string]*CookieData
}

type CookieData struct {
	Name      string
	Value     string
	Domain    string // Normalized domain (with leading dot for domain cookies)
	HostOnly  bool   // True if cookie should only be sent to exact host
	Path      string
	Expires   *time.Time
	MaxAge    int
	Secure    bool
	HttpOnly  bool
	SameSite  string
	CreatedAt time.Time
}

func NewCookieJar() *CookieJar {
	return &CookieJar{
		cookies: make(map[string]map[string]*CookieData),
	}
}

func cookieKey(path, name string) string {
	return path + "\x00" + name
}

func (j *CookieJar) Set(requestHost string, cookie *CookieData, requestSecure bool) {
	j.mu.Lock()
	defer j.mu.Unlock()

	requestHost = strings.ToLower(requestHost)
	if idx := strings.LastIndex(requestHost, ":"); idx != -1 {
		if !strings.Contains(requestHost, "]") || idx > strings.Index(requestHost, "]") {
			requestHost = requestHost[:idx]
		}
	}

	var domain string
	var hostOnly bool

	if cookie.Domain == "" {
		domain = requestHost
		hostOnly = true
	} else {
		domain = strings.ToLower(cookie.Domain)

		domainWithoutDot := strings.TrimPrefix(domain, ".")

		if !isDomainMatch(requestHost, domainWithoutDot) {
			return // Reject: can't set cookie for unrelated domain
		}

		domain = "." + domainWithoutDot
		hostOnly = false
	}

	if cookie.Secure && !requestSecure {
		return // Reject
	}

	path := cookie.Path
	if path == "" || path[0] != '/' {
		path = "/"
	}

	stored := &CookieData{
		Name:      cookie.Name,
		Value:     cookie.Value,
		Domain:    domain,
		HostOnly:  hostOnly,
		Path:      path,
		Expires:   cookie.Expires,
		MaxAge:    cookie.MaxAge,
		Secure:    cookie.Secure,
		HttpOnly:  cookie.HttpOnly,
		SameSite:  cookie.SameSite,
		CreatedAt: time.Now(),
	}

	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]*CookieData)
	}
	j.cookies[domain][cookieKey(path, cookie.Name)] = stored
}

func (j *CookieJar) Get(requestHost, requestPath string, requestSecure bool) []*CookieData {
	j.mu.RLock()
	defer j.mu.RUnlock()

	requestHost = strings.ToLower(requestHost)
	if idx := strings.LastIndex(requestHost, ":"); idx != -1 {
		if !strings.Contains(requestHost, "]") || idx > strings.Index(requestHost, "]") {
			requestHost = requestHost[:idx]
		}
	}

	if requestPath == "" {
		requestPath = "/"
	}

	now := time.Now()
	var matches []*CookieData

	for domain, domainCookies := range j.cookies {
		if !j.domainMatchesHost(domain, requestHost) {
			continue
		}

		for _, cookie := range domainCookies {
			if cookie.HostOnly && domain != requestHost {
				continue
			}

			if !isPathMatch(requestPath, cookie.Path) {
				continue
			}

			if cookie.Secure && !requestSecure {
				continue
			}

			if cookie.Expires != nil && cookie.Expires.Before(now) {
				continue
			}

			matches = append(matches, cookie)
		}
	}

	sort.Slice(matches, func(i, k int) bool {
		if len(matches[i].Path) != len(matches[k].Path) {
			return len(matches[i].Path) > len(matches[k].Path)
		}
		return matches[i].CreatedAt.Before(matches[k].CreatedAt)
	})

	return matches
}

func (j *CookieJar) GetAll() []CookieState {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	var result []CookieState

	for _, domainCookies := range j.cookies {
		for _, c := range domainCookies {
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			createdAt := c.CreatedAt
			result = append(result, CookieState{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				Path:      c.Path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: &createdAt,
			})
		}
	}

	sort.Slice(result, func(i, k int) bool {
		if result[i].Domain != result[k].Domain {
			return result[i].Domain < result[k].Domain
		}
		if result[i].Path != result[k].Path {
			return result[i].Path < result[k].Path
		}
		return result[i].Name < result[k].Name
	})

	return result
}

func (j *CookieJar) SetSimple(name, value, domain, path string, secure, httpOnly bool, sameSite string, maxAge int, expires *time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()

	hostOnly := false
	if domain == "" {
	} else {
		domain = strings.ToLower(domain)
		if !strings.HasPrefix(domain, ".") {
			hostOnly = true
		}
	}

	if path == "" {
		path = "/"
	}

	if j.cookies[domain] == nil {
		j.cookies[domain] = make(map[string]*CookieData)
	}
	j.cookies[domain][cookieKey(path, name)] = &CookieData{
		Name:      name,
		Value:     value,
		Domain:    domain,
		HostOnly:  hostOnly,
		Path:      path,
		Expires:   expires,
		MaxAge:    maxAge,
		Secure:    secure,
		HttpOnly:  httpOnly,
		SameSite:  sameSite,
		CreatedAt: time.Now(),
	}
}

func (j *CookieJar) Delete(name, domain string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if domain == "" {
		for d, domainCookies := range j.cookies {
			for key, cookie := range domainCookies {
				if cookie.Name == name {
					delete(domainCookies, key)
				}
			}
			if len(domainCookies) == 0 {
				delete(j.cookies, d)
			}
		}
	} else {
		domain = strings.ToLower(domain)
		domainCookies, ok := j.cookies[domain]
		if !ok {
			return
		}
		for key, cookie := range domainCookies {
			if cookie.Name == name {
				delete(domainCookies, key)
			}
		}
		if len(domainCookies) == 0 {
			delete(j.cookies, domain)
		}
	}
}

func (j *CookieJar) Clear() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = make(map[string]map[string]*CookieData)
}

func (j *CookieJar) ClearExpired() {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()
	for domain, domainCookies := range j.cookies {
		for key, cookie := range domainCookies {
			if cookie.Expires != nil && cookie.Expires.Before(now) {
				delete(domainCookies, key)
			}
		}
		if len(domainCookies) == 0 {
			delete(j.cookies, domain)
		}
	}
}

func (j *CookieJar) Count() int {
	j.mu.RLock()
	defer j.mu.RUnlock()

	count := 0
	for _, domainCookies := range j.cookies {
		count += len(domainCookies)
	}
	return count
}

func (j *CookieJar) Export() map[string][]CookieState {
	j.mu.RLock()
	defer j.mu.RUnlock()

	now := time.Now()
	result := make(map[string][]CookieState)

	for domain, domainCookies := range j.cookies {
		var cookies []CookieState
		for _, c := range domainCookies {
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			createdAt := c.CreatedAt
			cookies = append(cookies, CookieState{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				Path:      c.Path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: &createdAt,
			})
		}
		if len(cookies) > 0 {
			result[domain] = cookies
		}
	}

	return result
}

func (j *CookieJar) Import(cookies map[string][]CookieState) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()

	for domain, domainCookies := range cookies {
		if j.cookies[domain] == nil {
			j.cookies[domain] = make(map[string]*CookieData)
		}

		for _, c := range domainCookies {
			if c.Expires != nil && c.Expires.Before(now) {
				continue
			}

			path := c.Path
			if path == "" {
				path = "/"
			}

			hostOnly := !strings.HasPrefix(c.Domain, ".")

			createdAt := now
			if c.CreatedAt != nil {
				createdAt = *c.CreatedAt
			}

			j.cookies[domain][cookieKey(path, c.Name)] = &CookieData{
				Name:      c.Name,
				Value:     c.Value,
				Domain:    c.Domain,
				HostOnly:  hostOnly,
				Path:      path,
				Expires:   c.Expires,
				MaxAge:    c.MaxAge,
				Secure:    c.Secure,
				HttpOnly:  c.HttpOnly,
				SameSite:  c.SameSite,
				CreatedAt: createdAt,
			}
		}
	}
}

func (j *CookieJar) ImportV4(cookies []CookieState) {
	j.mu.Lock()
	defer j.mu.Unlock()

	now := time.Now()

	for _, c := range cookies {
		if c.Expires != nil && c.Expires.Before(now) {
			continue
		}

		domain := c.Domain
		hostOnly := false

		if domain == "" {
			domain = ""
		} else {
			domain = strings.ToLower(domain)
			if !strings.HasPrefix(domain, ".") {
				hostOnly = true
			}
		}

		path := c.Path
		if path == "" {
			path = "/"
		}

		if j.cookies[domain] == nil {
			j.cookies[domain] = make(map[string]*CookieData)
		}

		j.cookies[domain][cookieKey(path, c.Name)] = &CookieData{
			Name:      c.Name,
			Value:     c.Value,
			Domain:    domain,
			HostOnly:  hostOnly,
			Path:      path,
			Expires:   c.Expires,
			MaxAge:    c.MaxAge,
			Secure:    c.Secure,
			HttpOnly:  c.HttpOnly,
			SameSite:  c.SameSite,
			CreatedAt: now,
		}
	}
}

func (j *CookieJar) domainMatchesHost(cookieDomain, requestHost string) bool {
	if cookieDomain == "" {
		return true
	}

	if cookieDomain == requestHost {
		return true
	}

	if strings.HasPrefix(cookieDomain, ".") {
		domainWithoutDot := cookieDomain[1:]
		if requestHost == domainWithoutDot {
			return true
		}
		if strings.HasSuffix(requestHost, cookieDomain) {
			return true
		}
	}

	return false
}

func isDomainMatch(host, domain string) bool {
	if host == domain {
		return true
	}
	if strings.HasSuffix(host, "."+domain) {
		return true
	}
	return false
}

func isPathMatch(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}

	if strings.HasPrefix(requestPath, cookiePath) {
		if strings.HasSuffix(cookiePath, "/") {
			return true
		}
		if len(requestPath) > len(cookiePath) && requestPath[len(cookiePath)] == '/' {
			return true
		}
	}

	return false
}

func (j *CookieJar) BuildCookieHeader(requestHost, requestPath string, requestSecure bool) string {
	cookies := j.Get(requestHost, requestPath, requestSecure)
	if len(cookies) == 0 {
		return ""
	}

	var parts []string
	for _, c := range cookies {
		parts = append(parts, c.Name+"="+c.Value)
	}

	return strings.Join(parts, "; ")
}
