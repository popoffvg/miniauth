package tokens

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseScope(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "https://app.example.test/mcp", want: "https://app.example.test/mcp", ok: true},
		{raw: "HTTPS://App.Example.Test/mcp/", want: "https://app.example.test/mcp", ok: true},
		{raw: "https://app.example.test:443/mcp", want: "https://app.example.test/mcp", ok: true},
		{raw: "http://app.example.test:80", want: "http://app.example.test", ok: true},
		{raw: "https://app.example.test:8443/", want: "https://app.example.test:8443", ok: true},
		{raw: "ftp://app.example.test/mcp"},
		{raw: "https:///mcp"},
		{raw: "/mcp"},
		{raw: "https://user@app.example.test/mcp"},
		{raw: "https://app.example.test/mcp?x=1"},
		{raw: "https://app.example.test/mcp#top"},
		{raw: "https://app.example.test/mcp/../admin"},
		{raw: "https://app.example.test//mcp"},
		{raw: "https://app.example.test/a%2Fb"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			scope, err := ParseScope(tt.raw)
			if !tt.ok {
				require.ErrorIs(t, err, ErrScope)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, scope.String())
		})
	}
}

func TestScopesCover(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		target string
		want   bool
	}{
		{name: "no scope covers every url", target: "https://any.example.test/x", want: true},
		{name: "same path", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test/mcp", want: true},
		{name: "deeper path", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test/mcp/x", want: true},
		{name: "path with a trailing slash", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test/mcp/", want: true},
		{name: "query is not part of the path", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test/mcp?a=/x", want: true},
		{name: "segment border", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test/mcpx"},
		{name: "parent path", scopes: []string{"https://app.example.test/mcp/x"}, target: "https://app.example.test/mcp"},
		{name: "host scope", scopes: []string{"https://app.example.test/"}, target: "https://app.example.test/a/b", want: true},
		{name: "other scheme", scopes: []string{"https://app.example.test/mcp"}, target: "http://app.example.test/mcp"},
		{name: "other host", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test.evil.example/mcp"},
		{name: "default port", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test:443/mcp", want: true},
		{name: "other port", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test:8443/mcp"},
		{name: "case of the host", scopes: []string{"https://app.example.test/mcp"}, target: "https://APP.example.test/mcp", want: true},
		{name: "case of the path", scopes: []string{"https://app.example.test/mcp"}, target: "https://app.example.test/MCP"},
		{name: "second scope", scopes: []string{"https://app.example.test/api", "https://app.example.test/mcp"}, target: "https://app.example.test/mcp/x", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes, err := ParseScopes(tt.scopes)
			require.NoError(t, err)
			target, err := ParseTarget(tt.target)
			require.NoError(t, err)
			assert.Equal(t, tt.want, scopes.Covers(target))
		})
	}
}

func TestParseTargetRefusesAPathTheBackendCanReadOtherwise(t *testing.T) {
	for _, raw := range []string{
		"https://app.example.test/mcp/../admin",
		"https://app.example.test/mcp/./x",
		"https://app.example.test/mcp//x",
		"https://app.example.test/mcp%2F..%2Fadmin",
		"https://user@app.example.test/mcp",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := ParseTarget(raw)
			require.ErrorIs(t, err, ErrScope)
		})
	}
}

func TestScopeKeepsItsMeaningAfterStore(t *testing.T) {
	for _, raw := range []string{"https://app.example.test/%2541", "https://app.example.test/a%20b", "https://app.example.test/%C3%A9"} {
		t.Run(raw, func(t *testing.T) {
			scope, err := ParseScope(raw)
			require.NoError(t, err)
			var stored Scope
			require.NoError(t, stored.UnmarshalText([]byte(scope.String())))
			assert.Equal(t, scope, stored)
			assert.Equal(t, scope.String(), stored.String())
		})
	}

	scope, err := ParseScope("https://app.example.test/%2541")
	require.NoError(t, err)
	var stored Scope
	require.NoError(t, stored.UnmarshalText([]byte(scope.String())))
	upper, err := ParseTarget("https://app.example.test/A")
	require.NoError(t, err)
	assert.False(t, stored.Covers(upper), "a stored scope MUST NOT cover another path than the one given")
}
