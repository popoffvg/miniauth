package oauth

import (
	"net"
	"net/url"
	"strings"
)

// maxRedirectURILength keeps a stored URI and a redirect Location short.
const maxRedirectURILength = 2048

// RedirectURI is where the browser takes the authorization code back to the client.
// It is https, or http on a loopback host for a native client. It has no fragment and no user info.
type RedirectURI struct {
	value string
}

// ParseRedirectURI reads a registered or a requested redirect URI.
func ParseRedirectURI(raw string) (RedirectURI, error) {
	if raw == "" || len(raw) > maxRedirectURILength || strings.ContainsAny(raw, "#\r\n") {
		return RedirectURI{}, ErrRedirectURI
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" {
		return RedirectURI{}, ErrRedirectURI
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !loopbackHost(parsed.Hostname()) {
			return RedirectURI{}, ErrRedirectURI
		}
	default:
		return RedirectURI{}, ErrRedirectURI
	}
	return RedirectURI{value: raw}, nil
}

// Matches reports whether requested is this registered URI.
// A loopback http URI matches on any port: a native client listens on a port it picks at run time.
func (u RedirectURI) Matches(requested RedirectURI) bool {
	if u.value == "" {
		return false
	}
	if u.value == requested.value {
		return true
	}
	registered, err := url.Parse(u.value)
	if err != nil || registered.Scheme != "http" {
		return false
	}
	asked, err := url.Parse(requested.value)
	if err != nil {
		return false
	}
	return asked.Scheme == "http" &&
		asked.Hostname() == registered.Hostname() &&
		asked.EscapedPath() == registered.EscapedPath() &&
		asked.RawQuery == registered.RawQuery
}

// WithParams returns the URI with params added to its query. A param of the same name is replaced.
func (u RedirectURI) WithParams(params url.Values) string {
	parsed, err := url.Parse(u.value)
	if err != nil {
		return u.value
	}
	query := parsed.Query()
	for name, values := range params {
		query[name] = values
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (u RedirectURI) String() string {
	return u.value
}

// MarshalText encodes the URI.
func (u RedirectURI) MarshalText() ([]byte, error) {
	return []byte(u.value), nil
}

// UnmarshalText parses text with ParseRedirectURI.
func (u *RedirectURI) UnmarshalText(text []byte) error {
	parsed, err := ParseRedirectURI(string(text))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
