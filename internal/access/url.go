package access

import (
	"net/url"
	"strconv"
	"strings"
)

const (
	maxHostBytes = 255
	maxPathBytes = 2048
)

// Host is a lower-case host name with an optional port.
// Two hosts match only when they are equal, so a port is part of the host.
type Host struct {
	value string
}

// ParseHost parses a host such as "dash.example.test" or "127.0.0.1:8088".
func ParseHost(raw string) (Host, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" || len(s) > maxHostBytes || strings.ContainsAny(s, "/\\@?# %") || hasControl(s) {
		return Host{}, ErrHost
	}
	parsed, err := url.Parse("http://" + s)
	if err != nil || parsed.Host != s || parsed.Hostname() == "" || parsed.User != nil {
		return Host{}, ErrHost
	}
	if port := parsed.Port(); port != "" && !validPort(port) {
		return Host{}, ErrHost
	}
	return Host{value: s}, nil
}

func (h Host) String() string {
	return h.value
}

// PathPrefix is the path part of a resource URL.
// It starts with '/'. It has no trailing '/' unless it is "/".
// It has no empty, "." or ".." segment and no '%', so a prefix compares byte by byte with a raw path.
type PathPrefix struct {
	value string
}

// ParsePathPrefix parses a prefix such as "/" or "/mcp". A trailing '/' is removed.
func ParsePathPrefix(raw string) (PathPrefix, error) {
	s := strings.TrimSpace(raw)
	if len(s) > maxPathBytes || strings.Contains(s, "%") || !cleanPath(s) {
		return PathPrefix{}, ErrPathPrefix
	}
	if len(s) > 1 {
		s = strings.TrimSuffix(s, "/")
	}
	return PathPrefix{value: s}, nil
}

func (p PathPrefix) String() string {
	return p.value
}

// Covers reports whether path is the prefix or under it on a segment border.
// "/mcp" covers "/mcp" and "/mcp/x". It does not cover "/mcpx".
func (p PathPrefix) Covers(path string) bool {
	if p.value == "/" {
		return true
	}
	return path == p.value || strings.HasPrefix(path, p.value+"/")
}

// ResourceURL is the host and the path prefix of one resource.
type ResourceURL struct {
	Host   Host
	Prefix PathPrefix
}

// ParseResourceURL reads an absolute http or https URL such as "https://dash.example.test/mcp".
// It keeps only the host and the path prefix: a resource matches on host and path, not on the scheme.
// A URL with user info, a query, or a fragment is refused. An empty path is "/".
func ParseResourceURL(raw string) (ResourceURL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return ResourceURL{}, ErrResourceURL
	}
	host, err := ParseHost(parsed.Host)
	if err != nil {
		return ResourceURL{}, err
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	prefix, err := ParsePathPrefix(path)
	if err != nil {
		return ResourceURL{}, err
	}
	return ResourceURL{Host: host, Prefix: prefix}, nil
}

func (u ResourceURL) String() string {
	return u.Host.String() + u.Prefix.String()
}

// MarshalText encodes the host and the prefix, with no scheme: the scheme is not stored.
func (u ResourceURL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText parses text with ParseResourceURL, so it needs a scheme that MarshalText does not write.
func (u *ResourceURL) UnmarshalText(text []byte) error {
	parsed, err := ParseResourceURL(string(text))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// RequestURL is the URL the reverse proxy asks about. It has no query and no fragment.
type RequestURL struct {
	scheme string
	host   Host
	path   string
}

// ParseRequestURL reads the forwarded scheme, host, and request URI.
// The query and the fragment are dropped.
// A path with an empty, "." or ".." segment, or an encoded byte the path may carry raw, is refused:
// a backend can resolve such a path to a different resource than the one that matched.
func ParseRequestURL(scheme, host, requestURI string) (RequestURL, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme != "http" && scheme != "https" {
		return RequestURL{}, ErrRequestURL
	}
	parsedHost, err := ParseHost(host)
	if err != nil {
		return RequestURL{}, ErrRequestURL
	}
	path, _, _ := strings.Cut(requestURI, "?")
	path, _, _ = strings.Cut(path, "#")
	if len(path) > maxPathBytes || !cleanPath(path) || encodedPlainByte(path) {
		return RequestURL{}, ErrRequestURL
	}
	return RequestURL{scheme: scheme, host: parsedHost, path: path}, nil
}

// Host is the host of the URL.
func (u RequestURL) Host() Host {
	return u.host
}

// Path is the raw path of the URL.
func (u RequestURL) Path() string {
	return u.path
}

func (u RequestURL) String() string {
	if u.scheme == "" {
		return ""
	}
	return u.scheme + "://" + u.host.String() + u.path
}

// cleanPath reports a path that starts with '/' and has no empty, "." or ".." segment.
// "/" and "/a/" are clean: the last segment may be empty.
func cleanPath(path string) bool {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\?#") || hasControl(path) {
		return false
	}
	segments := strings.Split(path[1:], "/")
	for i, segment := range segments {
		if segment == "" && i != len(segments)-1 {
			return false
		}
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// encodedPlainByte reports a "%XY" that decodes to '/', '\', '%', or a byte a path may carry raw:
// an unreserved byte, a sub-delim, ':', or '@'. A backend that decodes twice turns "%25" into a new escape.
// A prefix has no '%', so the backend decodes such a path to one that a longer prefix covers.
func encodedPlainByte(path string) bool {
	for i := 0; i+2 < len(path); i++ {
		if path[i] != '%' {
			continue
		}
		decoded, err := strconv.ParseUint(path[i+1:i+3], 16, 8)
		if err == nil && strings.IndexByte(plainPathBytes, byte(decoded)) >= 0 {
			return true
		}
	}
	return false
}

const plainPathBytes = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@/\\%"

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func validPort(port string) bool {
	number, err := strconv.Atoi(port)
	return err == nil && number >= 1 && number <= 65535
}
