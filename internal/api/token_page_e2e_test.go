package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

var (
	clearTokenPattern  = regexp.MustCompile(`idp_[0-9A-Za-z]{43}`)
	revokeFormPattern  = regexp.MustCompile(`action="/tokens/([0-9a-f-]{36})/revoke"`)
	stepUpFormSentinel = `<h1>Confirm your password</h1>`
)

// testClock is a clock the test moves forward. The server reads it from other goroutines.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestTokenPageEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+4)
	fake := gofakeit.New(fakeSeed + 4)
	owner := &account{login: fake.Regex(`[a-z][a-z0-9]{7}`), password: fake.Password(true, true, true, true, false, 24)}
	other := &account{login: fake.Regex(`[a-z][a-z0-9]{7}`), password: fake.Password(true, true, true, true, false, 24)}

	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	for _, a := range []*account{owner, other} {
		login, loginErr := users.ParseLogin(a.login)
		require.NoError(t, loginErr)
		password, passwordErr := users.NewPassword(a.password)
		require.NoError(t, passwordErr)
		user, createErr := accounts.Create(ctx, login, password)
		require.NoError(t, createErr)
		a.id = user.ID
	}
	passwords, err := passwordstep.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)
	accessTokens := tokens.NewService(postgres.NewTokenRepository(pool))
	clock := &testClock{now: time.Now()}

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo)
	apiResource := createResource(t, grants, "api", server.Listener.Addr().String(), "/api")
	grantResource(t, grants, apiResource, access.UserSubject(owner.id))
	router, err := NewRouter(
		accounts,
		sessions.NewServiceWithClock(postgres.NewSessionRepository(pool), clock.Now),
		nil,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithAccessTokens(accessTokens),
		WithURLGrants(grants),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)

	ownerBrowser := newBrowser(t, server)
	otherBrowser := newBrowser(t, server)
	scope := base + "/api"
	var clearToken, tokenID string

	t.Run("no session redirects to the login page with a return URL", func(t *testing.T) {
		resp := get(t, newBrowser(t, server), base+tokensPath)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+"/login?return="+url.QueryEscape(base+tokensPath), resp.header.Get("Location"))
	})

	t.Run("the login returns to the token page", func(t *testing.T) {
		openLogin(t, ownerBrowser, base, base+tokensPath)
		resp := submitLogin(t, ownerBrowser, base, base, owner.login, owner.password)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+tokensPath, resp.header.Get("Location"))

		page := get(t, ownerBrowser, base+tokensPath)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, `action="/tokens"`)
		assert.Contains(t, page.body, "No tokens.")
	})

	t.Run("an old login asks for a step-up", func(t *testing.T) {
		clock.Advance(sessions.StepUpAfter + time.Minute)
		resp := submitTokenForm(t, ownerBrowser, base, base, "ci", scope)
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, stepUpFormSentinel)
		assert.Contains(t, resp.body, `name="password"`)
		assert.NotContains(t, resp.body, `name="login"`)
		assert.NotNil(t, findCookie(resp.cookies, flowCookieName))
		assert.Empty(t, listTokens(t, accessTokens, owner.id))
	})

	t.Run("a password of another login does not pass the step-up", func(t *testing.T) {
		resp := submitStepUp(t, ownerBrowser, base, other.login, other.password)
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, string(msgWrongCredentials))
		assert.Contains(t, resp.body, stepUpFormSentinel)

		again := submitTokenForm(t, ownerBrowser, base, base, "ci", scope)
		require.Equal(t, http.StatusOK, again.status)
		assert.Contains(t, again.body, stepUpFormSentinel)
		assert.Empty(t, listTokens(t, accessTokens, owner.id))
	})

	t.Run("the step-up returns to the token page and the token is shown once", func(t *testing.T) {
		resp := submitStepUp(t, ownerBrowser, base, "", owner.password)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+tokensPath, resp.header.Get("Location"))
		assert.Empty(t, sessionCookies(resp))

		made := submitTokenForm(t, ownerBrowser, base, base, "ci", scope)
		require.Equal(t, http.StatusOK, made.status)
		assert.Equal(t, "no-store", made.header.Get("Cache-Control"))
		clearToken = clearTokenPattern.FindString(made.body)
		require.NotEmpty(t, clearToken)
		assert.NotContains(t, made.header.Get("Location"), clearToken)

		list := listTokens(t, accessTokens, owner.id)
		require.Len(t, list, 1)
		assert.Equal(t, "ci", list[0].Name.String())
		assert.Equal(t, []string{scope}, list[0].Scopes.Strings())
		tokenID = list[0].ID.String()
	})

	t.Run("the token passes the auth check under its scope", func(t *testing.T) {
		require.NotEmpty(t, clearToken)
		inside := tokenCheck(t, server.Client(), base, clearToken, "/api/v1/items")
		assert.Equal(t, http.StatusOK, inside.status)
		assert.Equal(t, owner.login, inside.header.Get(headerAuthUser))
		assert.Equal(t, "token", inside.header.Get(headerAuthMethod))

		outside := tokenCheck(t, server.Client(), base, clearToken, "/admin")
		assert.Equal(t, http.StatusForbidden, outside.status)
	})

	t.Run("a later page does not show the token text", func(t *testing.T) {
		require.NotEmpty(t, clearToken)
		page := get(t, ownerBrowser, base+tokensPath)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "ci")
		assert.Contains(t, page.body, clearToken[:8])
		assert.Contains(t, page.body, scope)
		assert.NotContains(t, page.body, clearToken)
		matches := revokeFormPattern.FindStringSubmatch(page.body)
		require.Len(t, matches, 2)
		assert.Equal(t, tokenID, matches[1])

		home := get(t, ownerBrowser, base+"/")
		assert.NotContains(t, home.body, clearToken)
	})

	t.Run("a bad origin is refused", func(t *testing.T) {
		for _, origin := range []string{"", "https://evil.example.test"} {
			made := submitTokenForm(t, ownerBrowser, base, origin, "evil", "")
			assert.Equal(t, http.StatusForbidden, made.status, origin)
			revoked := submitRevoke(t, ownerBrowser, base, origin, tokenID)
			assert.Equal(t, http.StatusForbidden, revoked.status, origin)
		}
		list := listTokens(t, accessTokens, owner.id)
		require.Len(t, list, 1)
		assert.False(t, list[0].Revoked())
	})

	t.Run("a token of another user is 404", func(t *testing.T) {
		openLogin(t, otherBrowser, base, base+tokensPath)
		login := submitLogin(t, otherBrowser, base, base, other.login, other.password)
		require.Equal(t, http.StatusSeeOther, login.status)

		resp := submitRevoke(t, otherBrowser, base, base, tokenID)
		assert.Equal(t, http.StatusNotFound, resp.status)
		assert.Contains(t, resp.body, string(msgTokenNotFound))
		assert.NotContains(t, resp.body, clearToken[:8])

		malformed := submitRevoke(t, otherBrowser, base, base, "not-a-token-id")
		assert.Equal(t, http.StatusNotFound, malformed.status)

		assert.Equal(t, http.StatusOK, tokenCheck(t, server.Client(), base, clearToken, "/api").status)
	})

	t.Run("revoke ends the token", func(t *testing.T) {
		resp := submitRevoke(t, ownerBrowser, base, base, tokenID)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+tokensPath, resp.header.Get("Location"))

		assert.Equal(t, http.StatusUnauthorized, tokenCheck(t, server.Client(), base, clearToken, "/api").status)
		page := get(t, ownerBrowser, base+tokensPath)
		require.Equal(t, http.StatusOK, page.status)
		assert.NotContains(t, page.body, "/revoke")
		assert.NotContains(t, page.body, clearToken)
		list := listTokens(t, accessTokens, owner.id)
		require.Len(t, list, 1)
		assert.True(t, list[0].Revoked())
	})
}

type account struct {
	login    string
	password string
	id       users.ID
}

func submitTokenForm(t *testing.T, browser *http.Client, base, origin, name, scopes string) reply {
	t.Helper()
	form := url.Values{"name": {name}, "scopes": {scopes}}
	return postForm(t, browser, base+tokensPath, origin, form)
}

func submitRevoke(t *testing.T, browser *http.Client, base, origin, id string) reply {
	t.Helper()
	return postForm(t, browser, base+tokensPath+"/"+id+"/revoke", origin, url.Values{})
}

// submitStepUp sends login too, so the test shows that the step-up does not read it.
func submitStepUp(t *testing.T, browser *http.Client, base, login, password string) reply {
	t.Helper()
	form := url.Values{"password": {password}}
	if login != "" {
		form.Set("login", login)
	}
	return postForm(t, browser, base+"/login", base, form)
}

func postForm(t *testing.T, browser *http.Client, target, origin string, form url.Values) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return do(t, browser, req)
}

// tokenCheck sends the token the way a client behind the proxy does, for base<uri>.
func tokenCheck(t *testing.T, client *http.Client, base, clearToken, uri string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/auth/check", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+clearToken)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", strings.TrimPrefix(base, "https://"))
	req.Header.Set("X-Forwarded-Uri", uri)
	return do(t, client, req)
}

func listTokens(t *testing.T, accessTokens *tokens.Service, userID users.ID) []tokens.Token {
	t.Helper()
	list, err := accessTokens.List(t.Context(), userID)
	require.NoError(t, err)
	return list
}
