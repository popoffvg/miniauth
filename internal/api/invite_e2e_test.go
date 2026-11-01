package api

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestInviteEndToEnd(t *testing.T) {
	const adminToken = "bootstrap-token-for-tests"
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	var skew atomic.Int64
	clock := func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	inviteRepo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	invitations, err := invites.NewService(inviteRepo, clock, nil)
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	accounts := users.NewService(postgres.NewUserRepository(pool))
	grants := access.NewService(accessRepo, accounts)

	server := httptest.NewUnstartedServer(nil)
	host := server.Listener.Addr().String()
	base := "https://" + host
	app := createResource(t, grants, "app", host, "/app")
	createResource(t, grants, "other", host, "/other")
	groupRepo, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	groupStore, err := postgres.NewGroupAdminRepository(pool)
	require.NoError(t, err)
	groupAdmin, err := groupadmin.NewService(groupStore, grants)
	require.NoError(t, err)
	ops, err := groups.ParseName("ops")
	require.NoError(t, err)
	_, err = groupAdmin.Create(ctx, ops)
	require.NoError(t, err)
	require.NoError(t, groupAdmin.AddResource(ctx, ops, app))
	logs := &lockedBuffer{}
	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		groupRepo,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, adminToken),
		&readyState{ok: true},
		slog.New(slog.NewTextHandler(logs, nil)),
		WithURLGrants(grants),
		WithAccessAdmin(grants),
		WithInvites(invitations),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	defer server.Close()
	browser := newBrowser(t, server)

	admin := func(path, body string) reply {
		t.Helper()
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, base+path, strings.NewReader(body))
		require.NoError(t, reqErr)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		return do(t, server.Client(), req)
	}
	createInvite := func() (link, token string) {
		t.Helper()
		resp := admin("/api/v1/invites", `{"group":"ops"}`)
		require.Equal(t, http.StatusCreated, resp.status, resp.body)
		created := decodeReply[struct {
			Link      string    `json:"link"`
			Group     string    `json:"group"`
			ExpiresAt time.Time `json:"expires_at"`
		}](t, strings.NewReader(resp.body))
		assert.Equal(t, "ops", created.Group)
		assert.WithinDuration(t, clock().Add(invites.Lifetime), created.ExpiresAt, time.Minute)
		token, ok := strings.CutPrefix(created.Link, base+"/invite/")
		require.True(t, ok, created.Link)
		return created.Link, token
	}
	accept := func(origin, token, login string) reply {
		t.Helper()
		form := url.Values{"token": {token}, "login": {login}, "password": {"invited-password-1"}}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, base+"/invite/accept", strings.NewReader(form.Encode()))
		require.NoError(t, reqErr)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		return do(t, browser, req)
	}

	require.Equal(t, http.StatusNotFound, admin("/api/v1/invites", `{"group":"missing"}`).status)
	require.Equal(t, http.StatusBadRequest, admin("/api/v1/invites", `{"group":"-bad-"}`).status)
	link, token := createInvite()

	page := get(t, browser, link)
	require.Equal(t, http.StatusOK, page.status)
	assert.Equal(t, "no-referrer", page.header.Get("Referrer-Policy"))
	assert.Equal(t, "no-store", page.header.Get("Cache-Control"))
	assert.Contains(t, page.body, `name="token" value="`+token+`"`)
	echoReq, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	require.NoError(t, err)
	echoReq.Header.Set("X-Request-ID", token)
	assert.NotEqual(t, token, do(t, browser, echoReq).header.Get("X-Request-ID"))

	refused := accept("https://evil.example.test", token, "newcomer")
	assert.Equal(t, http.StatusForbidden, refused.status)

	require.Equal(t, http.StatusCreated, admin("/api/v1/users", `{"login":"taken","password":"taken-password-1"}`).status)
	taken := accept(base, token, "taken")
	require.Equal(t, http.StatusConflict, taken.status)
	assert.Contains(t, taken.body, string(msgInviteLoginUsed))
	assert.Empty(t, sessionCookies(taken))

	accepted := accept(base, token, "newcomer")
	require.Equal(t, http.StatusSeeOther, accepted.status, accepted.body)
	assert.Equal(t, base+"/", accepted.header.Get("Location"))
	require.Len(t, sessionCookies(accepted), 1)

	granted := forwardedCheck(t, browser, base, host, "/app/page")
	require.Equal(t, http.StatusOK, granted.status)
	assert.Equal(t, "newcomer", granted.header.Get(headerAuthUser))
	assert.Equal(t, http.StatusForbidden, forwardedCheck(t, browser, base, host, "/other/page").status)

	used := get(t, browser, link)
	assert.Equal(t, http.StatusGone, used.status)
	assert.Equal(t, http.StatusGone, accept(base, token, "second").status)
	unknown := get(t, browser, base+"/invite/"+strings.Repeat("A", len(token)))
	assert.Equal(t, http.StatusGone, unknown.status)
	assert.Equal(t, used.body, unknown.body, "an unknown link MUST look like a used one")

	expiredLink, expiredToken := createInvite()
	skew.Store(int64(invites.Lifetime + time.Second))
	assert.Equal(t, http.StatusGone, get(t, browser, expiredLink).status)
	assert.Equal(t, http.StatusGone, accept(base, expiredToken, "late").status)
	skew.Store(0)
	assert.Equal(t, http.StatusOK, get(t, browser, expiredLink).status, "the expiry MUST come from the clock")

	server.Close()
	logged := logs.String()
	assert.Contains(t, logged, "/invite/{token}")
	assert.NotContains(t, logged, token)
	assert.NotContains(t, logged, expiredToken)
}

// lockedBuffer is a log writer that server goroutines and the test share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestInviteWithoutAPublicURLOrASession(t *testing.T) {
	const adminToken = "bootstrap-token-for-tests"
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	inviteRepo, err := postgres.NewInviteRepository(pool)
	require.NoError(t, err)
	invitations, err := invites.NewService(inviteRepo, time.Now, nil)
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	accounts := users.NewService(postgres.NewUserRepository(pool))
	grants := access.NewService(accessRepo, accounts)
	createResource(t, grants, "app", "app.example.test", "/")
	const base = "https://id.example.test"
	newRouter := func(publicURL PublicURL) http.Handler {
		// The session store has no device store, so every session start fails.
		router, routerErr := NewRouter(accounts, sessions.NewService(newMemSessions()), nil, sessions.Domain{}, publicURL,
			hashToken(t, adminToken), &readyState{ok: true}, slog.New(slog.DiscardHandler),
			WithAccessAdmin(grants), WithInvites(invitations))
		require.NoError(t, routerErr)
		return router
	}
	createInvite := func(router http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/invites", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	t.Run("no public URL answers 503", func(t *testing.T) {
		rec := createInvite(newRouter(PublicURL{}))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json")
	})

	t.Run("a failed session start says the account exists", func(t *testing.T) {
		router := newRouter(mustPublicURL(t, base))
		created := createInvite(router)
		require.Equal(t, http.StatusCreated, created.Code, created.Body.String())
		link := decodeReply[struct {
			Link string `json:"link"`
		}](t, created.Body).Link
		token, ok := strings.CutPrefix(link, base+"/invite/")
		require.True(t, ok, link)
		form := url.Values{"token": {token}, "login": {"invitee"}, "password": {"invited-password-1"}}
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/invite/accept", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", base)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), string(msgInviteSignInFailed))
		assert.NotContains(t, rec.Body.String(), string(msgInviteFailed))
		assert.Contains(t, rec.Body.String(), `href="/login"`)
	})
}
