package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/popoffvg/miniauth/internal/access"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

const importAdminToken = "bootstrap-token-for-tests"

// importedSecret is a valid token that this test file alone uses.
const importedSecret = "idp_ImportedToken0123456789abcdefghijklmnopqrst"

func TestImportedTokenPassesTheAuthCheck(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	for _, login := range []string{"ada", "bea"} {
		password, passwordErr := users.NewPassword("test-password-1")
		require.NoError(t, passwordErr)
		_, err = accounts.Create(ctx, mustLogin(t, login), password)
		require.NoError(t, err)
	}
	ada, err := accounts.FindByLogin(ctx, mustLogin(t, "ada"))
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo)
	// Both hosts are granted, so a 403 on the other host comes from the token scope.
	for _, host := range []string{"mcp.example.test", "other.example.test"} {
		resource := createResource(t, grants, strings.Split(host, ".")[0], host, "/")
		grantResource(t, grants, resource, access.UserSubject(ada.ID))
	}
	logs := &strings.Builder{}
	router, err := NewRouter(accounts, sessions.NewService(postgres.NewSessionRepository(pool)), nil, mustDomain(t, ".example.test"), PublicURL{}, hashToken(t, importAdminToken), &readyState{ok: true}, slog.New(slog.NewTextHandler(logs, nil)), WithAccessTokens(tokens.NewService(postgres.NewTokenRepository(pool))), WithURLGrants(grants))
	require.NoError(t, err)

	body := importBody("ada", importedSecret, `"https://mcp.example.test/"`)
	first := postImport(t, router, importAdminToken, body)
	require.Equal(t, http.StatusCreated, first.Code, first.Body.String())
	var created importedToken
	require.NoError(t, json.Unmarshal(first.Body.Bytes(), &created))
	assert.Equal(t, "idp_Impo", created.Prefix.String())
	assert.Equal(t, "ci", created.Name.String())
	assert.Equal(t, []string{"https://mcp.example.test"}, tokens.Scopes(created.Scopes).Strings())

	under := authCheck(t, router, importedSecret, "mcp.example.test", "/tools/list")
	require.Equal(t, http.StatusOK, under.Code)
	assert.Equal(t, "ada", under.Header().Get(headerAuthUser))
	assert.Equal(t, "token", under.Header().Get(headerAuthMethod))
	outside := authCheck(t, router, importedSecret, "other.example.test", "/tools/list")
	require.Equal(t, http.StatusForbidden, outside.Code)

	again := postImport(t, router, importAdminToken, importBody("ada", importedSecret, `"https://other.example.test/"`))
	require.Equal(t, http.StatusOK, again.Code, again.Body.String())
	var same importedToken
	require.NoError(t, json.Unmarshal(again.Body.Bytes(), &same))
	assert.Equal(t, created.ID, same.ID)
	assert.Equal(t, []string{"https://mcp.example.test"}, tokens.Scopes(same.Scopes).Strings())
	stored, err := postgres.NewTokenRepository(pool).List(ctx, ada.ID)
	require.NoError(t, err)
	require.Len(t, stored, 1)

	taken := postImport(t, router, importAdminToken, importBody("bea", importedSecret, `"https://mcp.example.test/"`))
	require.Equal(t, http.StatusConflict, taken.Code)

	tests := []struct {
		name  string
		token string
		body  string
		want  int
	}{
		{name: "no admin token", body: body, want: http.StatusUnauthorized},
		{name: "unknown user", token: importAdminToken, body: importBody("cid", importedSecret, `"https://mcp.example.test/"`), want: http.StatusNotFound},
		{name: "bad token format", token: importAdminToken, body: importBody("ada", "idp_short", `"https://mcp.example.test/"`), want: http.StatusBadRequest},
		{name: "token with no marker", token: importAdminToken, body: importBody("ada", "xyz_ImportedToken0123456789abcdefghijklmnopqrst", `"https://mcp.example.test/"`), want: http.StatusBadRequest},
		{name: "scope is not a URL prefix", token: importAdminToken, body: importBody("ada", importedSecret, `"https://mcp.example.test/?q=1"`), want: http.StatusBadRequest},
		{name: "scope list is empty", token: importAdminToken, body: importBody("ada", importedSecret, ""), want: http.StatusBadRequest},
		{name: "login is not valid", token: importAdminToken, body: importBody("-", importedSecret, `"https://mcp.example.test/"`), want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postImport(t, router, tt.token, tt.body)
			require.Equal(t, tt.want, rec.Code, rec.Body.String())
			assert.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
			assert.NotContains(t, rec.Body.String(), importedSecret)
		})
	}

	for _, rec := range []*httptest.ResponseRecorder{first, again, taken} {
		assert.NotContains(t, rec.Body.String(), importedSecret)
	}
	assert.Contains(t, logs.String(), "/api/v1/tokens/import")
	assert.NotContains(t, logs.String(), importedSecret)
	assert.NotContains(t, logs.String(), "mcp.example.test")
}

func TestImportStoreFailureLogHasNoToken(t *testing.T) {
	accounts := &memRepo{}
	accounts.put(users.User{ID: users.NewID(), Login: mustLogin(t, "ada")})
	logs := &strings.Builder{}
	router, err := NewRouter(users.NewService(accounts), sessions.NewService(newMemSessions()), nil, sessions.Domain{}, PublicURL{}, hashToken(t, importAdminToken), &readyState{ok: true}, slog.New(slog.NewTextHandler(logs, nil)), WithAccessTokens(tokens.NewService(failTokens{})))
	require.NoError(t, err)

	req := importRequest(t, importAdminToken, importBody("ada", importedSecret, `"https://mcp.example.test/"`))
	req.Header.Set("X-Request-ID", importedSecret)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotEqual(t, importedSecret, rec.Header().Get("X-Request-ID"))
	assert.Contains(t, logs.String(), "miniauth: import token")
	assert.NotContains(t, logs.String(), importedSecret)
	assert.NotContains(t, rec.Body.String(), importedSecret)
}

func importBody(login, secret, scopes string) string {
	return `{"user":"` + login + `","name":"ci","scopes":[` + scopes + `],"token":"` + secret + `"}`
}

func importRequest(t *testing.T, adminToken, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/tokens/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	return req
}

func postImport(t *testing.T, router http.Handler, adminToken, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, importRequest(t, adminToken, body))
	return rec
}

func authCheck(t *testing.T, router http.Handler, secret, host, uri string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
