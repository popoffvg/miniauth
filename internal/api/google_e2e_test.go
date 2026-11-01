package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/providers/google"
	"github.com/popoffvg/miniauth/internal/providers/google/oidctest"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// laterLinks moves the clock of Link forward by shift, so a test can link after LinkTTL. fail makes Link fail.
type laterLinks struct {
	identitylink.Store
	shift atomic.Int64
	fail  atomic.Bool
}

func (l *laterLinks) Link(ctx context.Context, hash identitylink.SecretHash, userID users.ID, identityID users.IdentityID, now time.Time) (users.ExternalAccount, error) {
	if l.fail.Load() {
		return users.ExternalAccount{}, errors.New("database is down")
	}
	return l.Store.Link(ctx, hash, userID, identityID, now.Add(time.Duration(l.shift.Load())))
}

func TestGoogleLoginEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+4)
	fake := gofakeit.New(fakeSeed + 4)
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
	userPassword, err := users.NewPassword(rawPassword)
	require.NoError(t, err)
	account, err := accounts.Create(ctx, login, userPassword)
	require.NoError(t, err)
	passwords, err := password.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)

	provider := oidctest.New(t)
	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, nil)
	app := createResource(t, grants, "app", server.Listener.Addr().String(), "/app")
	grantResource(t, grants, app, access.UserSubject(account.ID))
	flowStore := postgres.NewFlowStore(pool)
	step, err := google.NewStep(google.Config{
		Issuer:       google.Issuer(provider.Issuer()),
		ClientID:     google.ParseClientID(oidctest.ClientID),
		ClientSecret: google.ParseClientSecret(oidctest.ClientSecret),
		RedirectURL:  google.RedirectURL(base + GoogleCallbackPath),
	}, accountRepo, flowStore, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = step.Close() })
	go step.Watch(ctx, time.Hour)
	require.Eventually(t, step.Available, 5*time.Second, 10*time.Millisecond)
	links := &laterLinks{Store: postgres.NewIdentityLinkRepository(pool)}

	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		nil,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(flowStore), passwords),
		WithGoogle(step, identitylink.NewService(links)),
		WithURLGrants(grants),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)

	countSessions := func() int64 {
		n, err := queries.CountSessions(ctx)
		require.NoError(t, err)
		return n
	}
	countPending := func() int64 {
		n, err := queries.CountPendingIdentityLinks(ctx)
		require.NoError(t, err)
		return n
	}
	linkedUser := func(subject string) (users.ID, bool) {
		row, err := queries.GetExternalIdentity(ctx, sqlcgen.GetExternalIdentityParams{
			Kind:    string(users.KindGoogle),
			Subject: pgtype.Text{String: subject, Valid: true},
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return users.ID{}, false
		}
		require.NoError(t, err)
		return users.IDFromBytes(row.UserID.Bytes), true
	}

	t.Run("a cross-origin post is refused", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		resp := postGoogle(t, browser, base, "https://evil.example.test")
		assert.Equal(t, http.StatusForbidden, resp.status)
	})

	t.Run("an unknown sub starts no session, then a password login links it", func(t *testing.T) {
		provider.SetSubject("google-sub-1")
		browser := newBrowser(t, server)
		page := openLogin(t, browser, base, base+"/app")
		assert.Contains(t, page.body, `action="/login/google"`)

		callback := googleCallback(t, browser, base, nil)
		require.Equal(t, http.StatusOK, callback.status)
		assert.Contains(t, callback.body, string(msgLinkGoogle))
		assert.Contains(t, callback.body, `name="password"`)
		assert.Empty(t, sessionCookies(callback))
		assert.Zero(t, countSessions())
		assert.Equal(t, int64(1), countPending())
		_, linked := linkedUser("google-sub-1")
		assert.False(t, linked)
		count, err := queries.CountUsers(t.Context())
		require.NoError(t, err)
		assert.Equal(t, int64(1), count, "an unknown sub creates no user")

		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusSeeOther, resp.status)
		confirmPage := base + linkPagePath + "?return=" + url.QueryEscape(base+"/app")
		assert.Equal(t, confirmPage, resp.header.Get("Location"))
		require.Len(t, sessionCookies(resp), 1)
		_, linked = linkedUser("google-sub-1")
		assert.False(t, linked, "a password login alone MUST NOT link")

		confirm := get(t, browser, confirmPage)
		require.Equal(t, http.StatusOK, confirm.status)
		assert.Contains(t, confirm.body, "Google account google-sub-1")

		links.fail.Store(true)
		failed := confirmLink(t, browser, base, base, "link", base+"/app")
		links.fail.Store(false)
		assert.Equal(t, http.StatusInternalServerError, failed.status)
		assert.Nil(t, findCookie(failed.cookies, pendingLinkCookieName), "a transient failure MUST keep the pending link cookie")
		assert.Equal(t, int64(1), countPending())

		done := confirmLink(t, browser, base, base, "link", base+"/app")
		require.Equal(t, http.StatusSeeOther, done.status, done.body)
		assert.Equal(t, base+"/app", done.header.Get("Location"))
		assert.Zero(t, countPending())
		_, linked = linkedUser("google-sub-1")
		assert.True(t, linked)
	})

	t.Run("a declined link is deleted", func(t *testing.T) {
		provider.SetSubject("google-sub-3")
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		require.Equal(t, http.StatusOK, googleCallback(t, browser, base, nil).status)
		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusSeeOther, resp.status)

		declined := confirmLink(t, browser, base, base, "skip", base+"/app")
		require.Equal(t, http.StatusSeeOther, declined.status, declined.body)
		assert.Equal(t, base+"/app", declined.header.Get("Location"))
		assert.Zero(t, countPending())
		_, linked := linkedUser("google-sub-3")
		assert.False(t, linked)
		assert.Equal(t, http.StatusFound, get(t, browser, base+linkPagePath).status, "with no pending link the page redirects")
	})

	t.Run("a Google login alone opens a session for the linked user", func(t *testing.T) {
		provider.SetSubject("google-sub-1")
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app/google")
		before := countSessions()

		callback := googleCallback(t, browser, base, nil)
		require.Equal(t, http.StatusSeeOther, callback.status)
		assert.Equal(t, base+"/app/google", callback.header.Get("Location"))
		require.Len(t, sessionCookies(callback), 1)
		assert.Equal(t, before+1, countSessions())

		check := forwardedCheck(t, browser, base, server.Listener.Addr().String(), "/app/google")
		require.Equal(t, http.StatusOK, check.status)
		assert.Equal(t, rawLogin, check.header.Get(headerAuthUser))
		assert.Equal(t, "google", check.header.Get(headerAuthMethod))
	})

	t.Run("a bad state is refused", func(t *testing.T) {
		provider.SetSubject("google-sub-1")
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		before := countSessions()

		var good url.Values
		bad := googleCallback(t, browser, base, func(q url.Values) {
			good = url.Values{"state": {q.Get("state")}, "code": {q.Get("code")}}
			q.Set("state", q.Get("state")+"x")
		})
		assert.Equal(t, http.StatusBadRequest, bad.status)
		assert.Contains(t, bad.body, string(msgGoogleFailed))
		assert.Empty(t, sessionCookies(bad))

		replay := get(t, browser, base+GoogleCallbackPath+"?"+good.Encode())
		assert.Equal(t, http.StatusBadRequest, replay.status, "the challenge is gone after one callback")
		assert.Empty(t, sessionCookies(replay))
		assert.Equal(t, before, countSessions())
	})

	t.Run("a bad nonce is refused", func(t *testing.T) {
		provider.SetSubject("google-sub-1")
		provider.SetClaim("nonce", "not-the-nonce-of-the-request")
		t.Cleanup(provider.ResetClaims)
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		before := countSessions()

		resp := googleCallback(t, browser, base, nil)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, string(msgGoogleFailed))
		assert.Empty(t, sessionCookies(resp))
		assert.Equal(t, before, countSessions())
	})

	t.Run("an expired pending link does not link", func(t *testing.T) {
		provider.SetSubject("google-sub-2")
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		callback := googleCallback(t, browser, base, nil)
		require.Equal(t, http.StatusOK, callback.status)
		require.Equal(t, int64(1), countPending())

		links.shift.Store(int64(identitylink.LinkTTL + time.Minute))
		t.Cleanup(func() { links.shift.Store(0) })
		resp := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusSeeOther, resp.status)
		require.Len(t, sessionCookies(resp), 1)
		late := confirmLink(t, browser, base, base, "link", base+"/app")
		require.Equal(t, http.StatusSeeOther, late.status, late.body)
		assert.Equal(t, base+"/app", late.header.Get("Location"))
		_, linked := linkedUser("google-sub-2")
		assert.False(t, linked)
	})
}

// confirmLink sends the form of the link confirm page. action is "link" or "skip".
func confirmLink(t *testing.T, browser *http.Client, base, origin, action, returnTo string) reply {
	t.Helper()
	form := url.Values{"action": {action}, "return": {returnTo}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+linkPagePath, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	return do(t, browser, req)
}

// postGoogle sends the Google button of the login page.
func postGoogle(t *testing.T, browser *http.Client, base, origin string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+googleLoginPath, strings.NewReader(""))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	return do(t, browser, req)
}

// googleCallback clicks the Google button, lets the fake provider grant, and opens the callback.
// edit, when set, changes the callback query first.
func googleCallback(t *testing.T, browser *http.Client, base string, edit func(url.Values)) reply {
	t.Helper()
	start := postGoogle(t, browser, base, base)
	require.Equal(t, http.StatusSeeOther, start.status)
	assert.NotNil(t, findCookie(start.cookies, googleVerifierCookieName))
	grant := get(t, browser, start.header.Get("Location"))
	require.Equal(t, http.StatusFound, grant.status)
	back, err := url.Parse(grant.header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, GoogleCallbackPath, back.Path)
	if edit != nil {
		query := back.Query()
		edit(query)
		back.RawQuery = query.Encode()
	}
	return get(t, browser, back.String())
}
