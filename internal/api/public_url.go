package api

import (
	"errors"
	"net/url"
	"strings"
)

// ErrPublicURL means the public URL is not an absolute http or https origin.
var ErrPublicURL = errors.New("api: public URL is not valid")

// PublicURL is the origin of the login page.
// The zero value builds a path with no host.
type PublicURL struct {
	origin string
}

// ParsePublicURL reads the origin from configuration.
// An empty value is the zero URL.
// The error MUST NOT contain raw.
func ParsePublicURL(raw string) (PublicURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return PublicURL{}, nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || !validPublicURL(parsed) {
		return PublicURL{}, ErrPublicURL
	}
	return PublicURL{origin: parsed.Scheme + "://" + parsed.Host}, nil
}

// Login is where an unauthenticated browser is sent.
func (u PublicURL) Login(returnTo string) string {
	loginURL := u.origin + "/login"
	if returnTo == "" {
		return loginURL
	}
	return loginURL + "?return=" + url.QueryEscape(returnTo)
}

// Host is compared with X-Forwarded-Host when the cookie domain is empty.
func (u PublicURL) Host() string {
	if u.origin == "" {
		return ""
	}
	parsed, err := url.Parse(u.origin)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func validPublicURL(u *url.URL) bool {
	if u == nil || u.Host == "" || u.Hostname() == "" || u.User != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if port := u.Port(); port != "" && !validPort(port) {
		return false
	}
	return u.Path == "" || u.Path == "/"
}
