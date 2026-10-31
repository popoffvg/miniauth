package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestLoginPageEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+3)
	fake := gofakeit.New(fakeSeed + 3)
	rawLogin := fake.Regex(`[a-z][a-z0-9]{7}`)
	rawPassword := fake.Password(true, true, true, true, false, 24)

	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	queries := sqlcgen.New(pool)

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	login, err := users.ParseLogin(rawLogin)
	require.NoError(t, err)
	password, err := users.NewPassword(rawPassword)
	require.NoError(t, err)
	account, err := accounts.Create(ctx, login, password)
	require.NoError(t, err)
	passwords, err := passwordstep.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, nil)
	app := createResource(t, grants, "app", server.Listener.Addr().String(), "/app")
	grantResource(t, grants, app, access.UserSubject(account.ID))
	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		nil,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithURLGrants(grants),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)
	browser := newBrowser(t, server)

	var firstSession *http.Cookie
	var firstDevice *http.Cookie

	countSessions := func() int64 {
		n, err := queries.CountSessions(ctx)
		require.NoError(t, err)
		return n
	}

	t.Run("a bad origin is refused", func(t *testing.T) {
		openLogin(t, browser, base, base+"/app")
		for _, origin := range []string{"", "https://evil.example.test", "http://" + server.Listener.Addr().String()} {
			resp := submitLogin(t, browser, base, origin, rawLogin, rawPassword)
			assert.Equal(t, http.StatusForbidden, resp.status, origin)
			assert.Empty(t, sessionCookies(resp), origin)
		}
		assert.Zero(t, countSessions())
	})

	t.Run("a wrong password starts no session", func(t *testing.T) {
		openLogin(t, browser, base, base+"/app")
		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword+"x")
		require.Equal(t, http.StatusOK, resp.status)
		body := resp.body
		assert.Contains(t, body, string(msgWrongCredentials))
		assert.NotContains(t, body, rawPassword)
		assert.Empty(t, sessionCookies(resp))
		assert.Zero(t, countSessions())
	})

	t.Run("the form lands on the return URL with a session", func(t *testing.T) {
		returnTo := base + "/app/dash?tab=1"
		page := openLogin(t, browser, base, returnTo)
		flowCookie := findCookie(page.cookies, flowCookieName)
		require.NotNil(t, flowCookie)
		assert.True(t, flowCookie.HttpOnly)
		assert.True(t, flowCookie.Secure)
		assert.Equal(t, http.SameSiteLaxMode, flowCookie.SameSite)

		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, returnTo, resp.header.Get("Location"))
		require.Len(t, sessionCookies(resp), 1)
		firstSession = sessionCookies(resp)[0]
		firstDevice = findCookie(resp.cookies, sessions.DeviceCookieName)
		require.NotNil(t, firstDevice)
		assert.True(t, firstDevice.HttpOnly)
		assert.True(t, firstDevice.Secure)
		assert.NotContains(t, resp.header.Get("Location"), flowCookie.Value)
		assert.Equal(t, int64(1), countSessions())

		check := forwardedCheck(t, browser, base, server.Listener.Addr().String(), "/app/dash?tab=1")
		require.Equal(t, http.StatusOK, check.status)
		assert.Equal(t, rawLogin, check.header.Get(headerAuthUser))
		assert.Equal(t, "password", check.header.Get(headerAuthMethod))

		again := submitLoginWithCookie(t, browser, base, flowCookie, rawLogin, rawPassword)
		assert.Equal(t, http.StatusBadRequest, again.status)
		assert.Empty(t, sessionCookies(again))
		assert.Equal(t, int64(1), countSessions())
	})

	t.Run("an outside return URL lands on the default page", func(t *testing.T) {
		openLogin(t, browser, base, "https://evil.example.test/steal")
		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+"/", resp.header.Get("Location"))

		device := findCookie(resp.cookies, sessions.DeviceCookieName)
		require.NotNil(t, device)
		assert.Equal(t, firstDevice.Value, device.Value)
		assert.Equal(t, int64(1), countSessions(), "two logins from one browser leave one session row")
		devices, err := queries.CountDevices(t.Context())
		require.NoError(t, err)
		assert.Equal(t, int64(1), devices)
		replaced := forwardedCheckWithSession(t, browser, base, server.Listener.Addr().String(), "/app", firstSession)
		assert.Equal(t, http.StatusFound, replaced.status)
		current := forwardedCheck(t, browser, base, server.Listener.Addr().String(), "/app")
		assert.Equal(t, http.StatusOK, current.status)

		home := get(t, browser, base+"/")
		require.Equal(t, http.StatusOK, home.status)
		assert.Contains(t, home.body, "You are signed in as "+rawLogin)
	})

	t.Run("the backoff answers 429", func(t *testing.T) {
		openLogin(t, browser, base, base+"/app")
		// The IP count already has one failure from the wrong password above.
		for range passwordstep.FreeFailures - 1 {
			resp := submitLogin(t, browser, base, base, rawLogin, rawPassword+"x")
			require.Equal(t, http.StatusOK, resp.status)
		}
		before := countSessions()
		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusTooManyRequests, resp.status)
		assert.NotEmpty(t, resp.header.Get("Retry-After"))
		assert.Contains(t, resp.body, string(msgTooSoon))
		assert.Empty(t, sessionCookies(resp))
		assert.Equal(t, before, countSessions())
	})
}

func newBrowser(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	// A copy, so two browsers of one server do not share a cookie jar.
	client := new(http.Client)
	*client = *server.Client()
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func openLogin(t *testing.T, browser *http.Client, base, returnTo string) reply {
	t.Helper()
	resp := get(t, browser, base+"/login?return="+url.QueryEscape(returnTo))
	require.Equal(t, http.StatusOK, resp.status)
	assert.Contains(t, resp.header.Get("Content-Type"), "text/html")
	assert.Contains(t, resp.body, `name="password"`)
	return resp
}

func submitLogin(t *testing.T, browser *http.Client, base, origin, login, password string) reply {
	t.Helper()
	req := loginRequest(t, base, login, password)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return do(t, browser, req)
}

// submitLoginWithCookie sends flowCookie instead of the cookie in the jar.
func submitLoginWithCookie(t *testing.T, browser *http.Client, base string, flowCookie *http.Cookie, login, password string) reply {
	t.Helper()
	req := loginRequest(t, base, login, password)
	req.Header.Set("Origin", base)
	req.AddCookie(&http.Cookie{Name: flowCookie.Name, Value: flowCookie.Value})
	plain := *browser
	plain.Jar = nil
	return do(t, &plain, req)
}

func loginRequest(t *testing.T, base, login, password string) *http.Request {
	t.Helper()
	form := url.Values{"login": {login}, "password": {password}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func get(t *testing.T, browser *http.Client, rawURL string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html")
	return do(t, browser, req)
}

// reply is one response, read and closed.
type reply struct {
	status  int
	header  http.Header
	body    string
	cookies []*http.Cookie
}

func do(t *testing.T, client *http.Client, req *http.Request) reply {
	t.Helper()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{status: resp.StatusCode, header: resp.Header, body: string(body), cookies: resp.Cookies()}
}

func sessionCookies(resp reply) []*http.Cookie {
	var found []*http.Cookie
	for _, cookie := range resp.cookies {
		if cookie.Name == sessions.CookieName && cookie.MaxAge >= 0 {
			found = append(found, cookie)
		}
	}
	return found
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// forwardedCheckWithSession sends session instead of the cookies in the jar.
func forwardedCheckWithSession(t *testing.T, browser *http.Client, base, host, uri string, session *http.Cookie) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/auth/check", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	plain := *browser
	plain.Jar = nil
	return do(t, &plain, req)
}

// forwardedCheck calls /auth/check with the headers Traefik sends for host and uri.
func forwardedCheck(t *testing.T, browser *http.Client, base, host, uri string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/auth/check", nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	return do(t, browser, req)
}
