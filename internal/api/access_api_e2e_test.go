package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestAccessAPIGrantAndRevokeEndToEnd(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accounts := users.NewService(postgres.NewUserRepository(pool))
	browser := sessions.NewService(postgres.NewSessionRepository(pool))
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, accounts)
	groupRepo, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	router, err := NewRouter(accounts, browser, groupRepo, mustDomain(t, ".example.test"), mustPublicURL(t, "https://id.example.test"), hashToken(t, accessAdminToken), &readyState{ok: true}, slog.New(slog.DiscardHandler),
		WithURLGrants(grants), WithAccessAdmin(grants))
	require.NoError(t, err)
	send := func(method, path, body string) *httptest.ResponseRecorder {
		return sendAccess(t, router, accessAdminToken, "application/json", method, path, body)
	}

	user := send(http.MethodPost, "/api/v1/users", `{"login":"ada","password":"correct horse battery staple"}`)
	require.Equal(t, http.StatusCreated, user.Code, user.Body.String())
	created := decodeReply[createdUser](t, user.Body)
	id, _, err := browser.Start(ctx, created.ID, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	check := func() int {
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/auth/check", nil)
		req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: id.CookieValue()})
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "dash.example.test")
		req.Header.Set("X-Forwarded-Uri", "/boards/1?tab=x")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec.Code
	}

	resource := send(http.MethodPost, "/api/v1/resources", `{"name":"dashboards","url":"https://dash.example.test/"}`)
	require.Equal(t, http.StatusCreated, resource.Code, resource.Body.String())
	require.Equal(t, http.StatusForbidden, check(), "a resource with no grant MUST deny")

	grantRec := send(http.MethodPost, "/api/v1/grants", `{"user":"ada","resource":"dashboards"}`)
	require.Equal(t, http.StatusCreated, grantRec.Code, grantRec.Body.String())
	grant := decodeReply[grantText](t, grantRec.Body)
	assert.Equal(t, "ada", grant.User)
	assert.Equal(t, "dash.example.test/", grant.Resource.URL)
	require.Equal(t, http.StatusOK, check())

	listed := send(http.MethodGet, "/api/v1/grants?user=ada&resource=dashboards", "")
	require.Equal(t, http.StatusOK, listed.Code, listed.Body.String())
	rows := decodeReply[struct{ Grants []grantText }](t, listed.Body).Grants
	require.Len(t, rows, 1)
	assert.Equal(t, grant.ID, rows[0].ID)

	require.Equal(t, http.StatusNoContent, send(http.MethodDelete, "/api/v1/grants/"+grant.ID, "").Code)
	require.Equal(t, http.StatusForbidden, check(), "a revoke MUST apply to the next check")
	require.Equal(t, http.StatusNotFound, send(http.MethodDelete, "/api/v1/grants/"+grant.ID, "").Code)

	require.Equal(t, http.StatusNoContent, send(http.MethodDelete, "/api/v1/resources/dashboards", "").Code)
	require.Equal(t, http.StatusNotFound, send(http.MethodDelete, "/api/v1/resources/dashboards", "").Code)
}
