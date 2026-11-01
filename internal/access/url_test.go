package access

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: " Dash.Example.Test ", want: "dash.example.test", ok: true},
		{raw: "127.0.0.1:8088", want: "127.0.0.1:8088", ok: true},
		{raw: "[2001:db8::1]:443", want: "[2001:db8::1]:443", ok: true},
		{raw: ""},
		{raw: "dash.example.test/x"},
		{raw: "user@dash.example.test"},
		{raw: "dash.example.test:99999"},
		{raw: "dash example.test"},
		{raw: "dash\r\n.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseHost(tt.raw)
			if !tt.ok {
				require.ErrorIs(t, err, ErrHost)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestParsePathPrefix(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "/", want: "/", ok: true},
		{raw: "/mcp", want: "/mcp", ok: true},
		{raw: "/mcp/", want: "/mcp", ok: true},
		{raw: "/a/b", want: "/a/b", ok: true},
		{raw: ""},
		{raw: "mcp"},
		{raw: "//"},
		{raw: "/a//b"},
		{raw: "/a/../b"},
		{raw: "/a/./b"},
		{raw: "/a%2Fb"},
		{raw: "/a?b"},
		{raw: "/a\\b"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParsePathPrefix(tt.raw)
			if !tt.ok {
				require.ErrorIs(t, err, ErrPathPrefix)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestPathPrefixCovers(t *testing.T) {
	tests := []struct {
		prefix string
		path   string
		want   bool
	}{
		{prefix: "/", path: "/", want: true},
		{prefix: "/", path: "/anything", want: true},
		{prefix: "/mcp", path: "/mcp", want: true},
		{prefix: "/mcp", path: "/mcp/", want: true},
		{prefix: "/mcp", path: "/mcp/tools", want: true},
		{prefix: "/mcp", path: "/mcpx", want: false},
		{prefix: "/mcp", path: "/", want: false},
		{prefix: "/mcp/admin", path: "/mcp", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.prefix+" "+tt.path, func(t *testing.T) {
			prefix, err := ParsePathPrefix(tt.prefix)
			require.NoError(t, err)
			assert.Equal(t, tt.want, prefix.Covers(tt.path))
		})
	}
}

func TestParseRequestURL(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		host   string
		uri    string
		want   string
		ok     bool
	}{
		{name: "query is dropped", scheme: "https", host: "Dash.Example.Test", uri: "/a/b?token=x", want: "https://dash.example.test/a/b", ok: true},
		{name: "fragment is dropped", scheme: "HTTP", host: "dash.example.test", uri: "/a#x", want: "http://dash.example.test/a", ok: true},
		{name: "root", scheme: "https", host: "dash.example.test", uri: "/", want: "https://dash.example.test/", ok: true},
		{name: "other scheme", scheme: "ftp", host: "dash.example.test", uri: "/"},
		{name: "missing host", scheme: "https", host: "", uri: "/"},
		{name: "relative path", scheme: "https", host: "dash.example.test", uri: "a"},
		{name: "dot dot segment", scheme: "https", host: "dash.example.test", uri: "/public/../admin"},
		{name: "empty segment", scheme: "https", host: "dash.example.test", uri: "/public//admin"},
		{name: "encoded slash", scheme: "https", host: "dash.example.test", uri: "/public%2F..%2Fadmin"},
		{name: "encoded dot", scheme: "https", host: "dash.example.test", uri: "/public/%2e%2e/admin"},
		{name: "backslash", scheme: "https", host: "dash.example.test", uri: "/public\\admin"},
		{name: "encoded letter", scheme: "https", host: "dash.example.test", uri: "/%61dmin"},
		{name: "encoded upper case letter", scheme: "https", host: "dash.example.test", uri: "/%41dmin"},
		{name: "encoded digit", scheme: "https", host: "dash.example.test", uri: "/v%31"},
		{name: "encoded tilde", scheme: "https", host: "dash.example.test", uri: "/%7Euser"},
		{name: "encoded sub-delim", scheme: "https", host: "dash.example.test", uri: "/a%21b"},
		{name: "encoded colon", scheme: "https", host: "dash.example.test", uri: "/a%3Ab"},
		{name: "encoded space", scheme: "https", host: "dash.example.test", uri: "/a%20b", want: "https://dash.example.test/a%20b", ok: true},
		{name: "encoded percent", scheme: "https", host: "dash.example.test", uri: "/a%25b"},
		{name: "double-encoded dot dot", scheme: "https", host: "dash.example.test", uri: "/public/%252e%252e/admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRequestURL(tt.scheme, tt.host, tt.uri)
			if !tt.ok {
				require.ErrorIs(t, err, ErrRequestURL)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestMatchLongestPrefixOnTheSameHost(t *testing.T) {
	resources := []Resource{
		resource(t, "root", "dash.example.test", "/"),
		resource(t, "mcp", "dash.example.test", "/mcp"),
		resource(t, "mcp-admin", "dash.example.test", "/mcp/admin"),
		resource(t, "other", "other.example.test", "/mcp/admin/deep"),
	}
	tests := []struct {
		uri  string
		want string
	}{
		{uri: "/", want: "root"},
		{uri: "/mcpx", want: "root"},
		{uri: "/mcp", want: "mcp"},
		{uri: "/mcp/tools", want: "mcp"},
		{uri: "/mcp/admin", want: "mcp-admin"},
		{uri: "/mcp/admin/deep", want: "mcp-admin"},
	}
	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			target, err := ParseRequestURL("https", "dash.example.test", tt.uri)
			require.NoError(t, err)
			got, ok := Match(resources, target)
			require.True(t, ok)
			assert.Equal(t, tt.want, got.Name.String())
		})
	}

	target, err := ParseRequestURL("https", "dash.example.test", "/mcp")
	require.NoError(t, err)
	_, ok := Match(resources[3:], target)
	assert.False(t, ok, "a resource on another host MUST NOT match")
}

func resource(t *testing.T, rawName, rawHost, rawPrefix string) Resource {
	t.Helper()
	name, err := ParseResourceName(rawName)
	require.NoError(t, err)
	host, err := ParseHost(rawHost)
	require.NoError(t, err)
	prefix, err := ParsePathPrefix(rawPrefix)
	require.NoError(t, err)
	return Resource{Name: name, URL: ResourceURL{Host: host, Prefix: prefix}}
}

func TestParseResourceURL(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		err  error
	}{
		{raw: "https://dash.example.test/", want: "dash.example.test/"},
		{raw: "https://Dash.Example.Test", want: "dash.example.test/"},
		{raw: "HTTPS://dash.example.test/mcp/", want: "dash.example.test/mcp"},
		{raw: "http://127.0.0.1:8088/app", want: "127.0.0.1:8088/app"},
		{raw: "ftp://dash.example.test/", err: ErrResourceURL},
		{raw: "dash.example.test/mcp", err: ErrResourceURL},
		{raw: "https://user@dash.example.test/", err: ErrResourceURL},
		{raw: "https://dash.example.test/?x=1", err: ErrResourceURL},
		{raw: "https://dash.example.test/?", err: ErrResourceURL},
		{raw: "https://dash.example.test/#top", err: ErrResourceURL},
		{raw: "https:dash.example.test", err: ErrResourceURL},
		{raw: "https:///mcp", err: ErrHost},
		{raw: "https://dash.example.test/a/../b", err: ErrPathPrefix},
		{raw: "https://dash.example.test/a%2Fb", err: ErrPathPrefix},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseResourceURL(tt.raw)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
