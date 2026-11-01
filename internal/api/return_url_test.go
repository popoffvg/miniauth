package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/sessions"
)

func TestParseReturnURL(t *testing.T) {
	parent, err := sessions.ParseDomain(".example.test")
	require.NoError(t, err)
	public := mustPublicURL(t, "https://id.example.test")
	const root = "https://id.example.test/"
	tests := []struct {
		name   string
		raw    string
		domain sessions.Domain
		want   string
	}{
		{name: "subdomain", raw: "https://app.example.test/dash?x=1", domain: parent, want: "https://app.example.test/dash?x=1"},
		{name: "parent itself", raw: "https://example.test/", domain: parent, want: "https://example.test/"},
		{name: "port", raw: "https://app.example.test:8443/", domain: parent, want: "https://app.example.test:8443/"},
		{name: "upper case host", raw: "https://APP.example.test/", domain: parent, want: "https://APP.example.test/"},
		{name: "empty", raw: "", domain: parent, want: root},
		{name: "http", raw: "http://app.example.test/", domain: parent, want: root},
		{name: "other site", raw: "https://evil.test/", domain: parent, want: root},
		{name: "suffix trick", raw: "https://evilexample.test/", domain: parent, want: root},
		{name: "user info", raw: "https://app.example.test@evil.test/", domain: parent, want: root},
		{name: "relative", raw: "/dash", domain: parent, want: root},
		{name: "scheme relative", raw: "//evil.test/", domain: parent, want: root},
		{name: "javascript", raw: "javascript:alert(1)", domain: parent, want: root},
		{name: "backslash host", raw: `https://evil.test\.example.test/`, domain: parent, want: root},
		{name: "bad port", raw: "https://app.example.test:99999/", domain: parent, want: root},
		{name: "public host with no domain", raw: "https://id.example.test/after", want: "https://id.example.test/after"},
		{name: "subdomain with no domain", raw: "https://app.example.test/", want: root},
		{name: "public host with its default port", raw: "https://id.example.test:443/after", want: "https://id.example.test:443/after"},
		{name: "public host with another port", raw: "https://id.example.test:8443/after", want: root},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseReturnURL(tt.raw, tt.domain, public).String())
		})
	}
	assert.Equal(t, "/", ParseReturnURL("https://evil.test/", sessions.Domain{}, PublicURL{}).String())
}
