package oauth

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRedirectURIAcceptsHTTPSAndLoopback(t *testing.T) {
	for _, raw := range []string{
		"https://app.example.test/callback",
		"http://localhost/callback",
		"http://127.0.0.1:33418/callback",
		"http://[::1]:8080/cb?x=1",
	} {
		_, err := ParseRedirectURI(raw)
		assert.NoError(t, err, raw)
	}
}

func TestParseRedirectURIRefusesOtherURIs(t *testing.T) {
	for _, raw := range []string{
		"",
		"http://app.example.test/callback",
		"https://app.example.test/callback#frag",
		"https://user@app.example.test/callback",
		"javascript:alert(1)",
		"custom-scheme:/callback",
		"/callback",
		"https:///callback",
		"https://app.example.test/\r\nx",
	} {
		_, err := ParseRedirectURI(raw)
		assert.ErrorIs(t, err, ErrRedirectURI, raw)
	}
}

func TestRedirectURIMatchesLoopbackOnAnyPort(t *testing.T) {
	registered := mustRedirectURI(t, "http://localhost/callback")
	assert.True(t, registered.Matches(mustRedirectURI(t, "http://localhost:51234/callback")))
	assert.False(t, registered.Matches(mustRedirectURI(t, "http://localhost:51234/other")))
	assert.False(t, registered.Matches(mustRedirectURI(t, "http://127.0.0.1:51234/callback")))
	assert.False(t, registered.Matches(mustRedirectURI(t, "https://localhost/callback")))
}

func TestRedirectURIMatchesHTTPSExactly(t *testing.T) {
	registered := mustRedirectURI(t, "https://app.example.test/callback")
	assert.True(t, registered.Matches(mustRedirectURI(t, "https://app.example.test/callback")))
	assert.False(t, registered.Matches(mustRedirectURI(t, "https://app.example.test:8443/callback")))
	assert.False(t, registered.Matches(mustRedirectURI(t, "https://app.example.test/callback/")))
	assert.False(t, RedirectURI{}.Matches(registered))
}

func TestRedirectURIWithParamsKeepsTheQuery(t *testing.T) {
	uri := mustRedirectURI(t, "http://127.0.0.1:9/cb?x=1")
	got, err := url.Parse(uri.WithParams(url.Values{"code": {"abc"}, "state": {"s t"}}))
	require.NoError(t, err)
	assert.Equal(t, "1", got.Query().Get("x"))
	assert.Equal(t, "abc", got.Query().Get("code"))
	assert.Equal(t, "s t", got.Query().Get("state"))
	assert.Equal(t, "/cb", got.Path)
}

func mustRedirectURI(t *testing.T, raw string) RedirectURI {
	t.Helper()
	uri, err := ParseRedirectURI(raw)
	require.NoError(t, err)
	return uri
}
