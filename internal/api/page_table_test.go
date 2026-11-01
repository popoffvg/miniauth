package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/views"
)

func TestTokenTableFiltersByStatusAndQuery(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	token := func(raw string, change func(*tokens.Token)) tokens.Token {
		name, err := tokens.ParseName(raw)
		require.NoError(t, err)
		made := tokens.Token{ID: tokens.NewID(), Name: name, CreatedAt: now.Add(-time.Hour)}
		change(&made)
		return made
	}
	list := []tokens.Token{
		token("ci", func(*tokens.Token) {}),
		token("deploy", func(t *tokens.Token) { t.RevokedAt = now.Add(-time.Minute) }),
		token("backup", func(t *tokens.Token) { t.ExpiresAt = now }),
		token("old-deploy", func(t *tokens.Token) { t.ExpiresAt = now.Add(-time.Hour); t.RevokedAt = now.Add(-2 * time.Hour) }),
	}
	tests := []struct {
		query string
		want  []string
	}{
		{query: "", want: []string{"ci", "deploy", "backup", "old-deploy"}},
		{query: "?status=active", want: []string{"ci"}},
		{query: "?status=expired", want: []string{"backup"}},
		{query: "?status=revoked", want: []string{"deploy", "old-deploy"}},
		{query: "?q=DEPLOY", want: []string{"deploy", "old-deploy"}},
		{query: "?q=deploy&status=revoked", want: []string{"deploy", "old-deploy"}},
		{query: "?status=unknown", want: []string{"ci", "deploy", "backup", "old-deploy"}},
		{query: "?q=nothing", want: nil},
	}
	for _, tt := range tests {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tokensPath+tt.query, nil)
		table := newTokenTable(req, list, now)
		var names []string
		for _, row := range table.Rows {
			names = append(names, row.Token.Name.String())
		}
		assert.Equal(t, tt.want, names, tt.query)
		assert.Equal(t, len(list), table.Total, tt.query)
	}
}

func TestDoneNoticeShowsOnlyAKnownFlag(t *testing.T) {
	known := httptest.NewRequestWithContext(t.Context(), http.MethodGet, withDone(tokensPath, doneTokenRevoked), nil)
	assert.Equal(t, views.Message("The token is revoked."), doneNotice(known))
	unknown := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tokensPath+"?done=<script>", nil)
	assert.Empty(t, doneNotice(unknown))
}

func TestRefusedTokenFormKeepsTheFields(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tokensPath, nil)
	req.PostForm = map[string][]string{"name": {"ci"}, "scopes": {"ftp://bad"}, "expires": {"2027-01-01"}}
	form := refusedTokenForm(req, msgScopeNotValid)
	assert.Equal(t, views.TokenForm{Name: "ci", Scopes: "ftp://bad", Expires: "2027-01-01", Field: views.TokenFieldScopes, Message: msgScopeNotValid}, form)
	assert.Equal(t, views.TokenForm{}, refusedTokenForm(req, msgTokenNotFound), "a message of no field keeps no form")
}

func TestAppStylesheetIsServed(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, appCSSPath, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/css; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Contains(t, rec.Body.String(), "prefers-color-scheme: dark")
}
