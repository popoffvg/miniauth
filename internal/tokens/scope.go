package tokens

import (
	"net/url"
	"path"
	"strings"
)

// Scope is a URL prefix: scheme, host, and path.
// It covers a URL on a path segment border: "/mcp" covers "/mcp" and "/mcp/x", not "/mcpx".
type Scope struct {
	scheme string
	host   string
	// path has no trailing slash. An empty path covers the whole host.
	path string
}

// Target is the URL a request asks for. The query is not part of it.
type Target struct {
	scheme string
	host   string
	path   string
}

// ParseScope reads an http or https URL with no query, fragment, or user info.
// The path MUST be clean: no "." or ".." segment and no empty segment.
func ParseScope(raw string) (Scope, error) {
	scheme, host, clean, ok := parseURLPrefix(raw)
	if !ok {
		return Scope{}, ErrScope
	}
	return Scope{scheme: scheme, host: host, path: strings.TrimSuffix(clean, "/")}, nil
}

// ParseTarget reads the URL a request asks for. The query and fragment are dropped.
// A path that is not clean, or that has an encoded slash, is an error:
// the backend can read such a path as a different one.
func ParseTarget(raw string) (Target, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, ErrScope
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	scheme, host, clean, ok := parseURLPrefix(u.String())
	if !ok {
		return Target{}, ErrScope
	}
	return Target{scheme: scheme, host: host, path: clean}, nil
}

// Covers reports whether target is under s.
func (s Scope) Covers(target Target) bool {
	if s.scheme != target.scheme || s.host != target.host {
		return false
	}
	if s.path == "" || target.path == s.path {
		return true
	}
	return strings.HasPrefix(target.path, s.path+"/")
}

// String is the stored form.
func (s Scope) String() string {
	return s.scheme + "://" + s.host + s.path
}

// Scopes is the set of URL prefixes of one token. An empty set covers every URL.
type Scopes []Scope

// Covers reports whether one scope covers target.
func (s Scopes) Covers(target Target) bool {
	if len(s) == 0 {
		return true
	}
	for _, scope := range s {
		if scope.Covers(target) {
			return true
		}
	}
	return false
}

// Unlimited reports whether the set covers every URL.
func (s Scopes) Unlimited() bool {
	return len(s) == 0
}

// Strings returns the stored forms.
func (s Scopes) Strings() []string {
	out := make([]string, len(s))
	for i, scope := range s {
		out[i] = scope.String()
	}
	return out
}

// ParseScopes parses each value with ParseScope.
func ParseScopes(raw []string) (Scopes, error) {
	out := make(Scopes, 0, len(raw))
	for _, value := range raw {
		scope, err := ParseScope(value)
		if err != nil {
			return nil, err
		}
		out = append(out, scope)
	}
	return out, nil
}

// parseURLPrefix returns the lower-case scheme, the lower-case host without a default port, and the decoded path.
func parseURLPrefix(raw string) (scheme, host, cleanPath string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", "", "", false
	}
	scheme = strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" || u.Hostname() == "" {
		return "", "", "", false
	}
	host = strings.ToLower(u.Host)
	host = strings.TrimSuffix(host, defaultPort(scheme))
	if strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") {
		return "", "", "", false
	}
	cleanPath = u.Path
	if cleanPath == "" {
		cleanPath = "/"
	}
	if !isCleanPath(cleanPath) {
		return "", "", "", false
	}
	return scheme, host, cleanPath, true
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return ":443"
	}
	return ":80"
}

func isCleanPath(p string) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned == p
}
