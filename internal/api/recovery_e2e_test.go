package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
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
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// mailbox is a recovery.Mailer that keeps each mail for the test.
type mailbox struct {
	mails chan recovery.Mail
}

func (m *mailbox) Send(_ context.Context, mail recovery.Mail) error {
	m.mails <- mail
	return nil
}

func (m *mailbox) next(t *testing.T) recovery.Mail {
	t.Helper()
	select {
	case mail := <-m.mails:
		return mail
	case <-time.After(10 * time.Second):
		t.Fatal("no mail arrived")
		return recovery.Mail{}
	}
}

var resetLinkInMail = regexp.MustCompile(`https://\S+/recover/[A-Za-z0-9_-]{43}`)

func TestPasswordRecoveryEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+4)
	fake := gofakeit.New(fakeSeed + 4)
	rawEmail := fake.Regex(`[a-z][a-z0-9]{7}`) + "@example.test"
	oldPassword := fake.Password(true, true, true, true, false, 24)
	newPassword := fake.Password(true, true, true, true, false, 24)

	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	queries := sqlcgen.New(pool)

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	email, err := users.ParseEmail(rawEmail)
	require.NoError(t, err)
	password, err := users.NewPassword(oldPassword)
	require.NoError(t, err)
	account, err := accounts.Create(ctx, email.Login(), password)
	require.NoError(t, err)
	passwords, err := passwordstep.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	publicURL := mustPublicURL(t, base)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, nil)
	app := createResource(t, grants, "app", server.Listener.Addr().String(), "/app")
	grantResource(t, grants, app, access.UserSubject(account.ID))
	mails := &mailbox{mails: make(chan recovery.Mail, recovery.QueueSize)}
	clock := &testClock{now: time.Now().UTC()}
	recoveries, err := recovery.NewService(
		postgres.NewPasswordResetRepository(pool),
		postgres.NewRecoveryAttemptRepository(pool),
		mails,
		publicURL,
		recovery.WithClock(clock.Now),
	)
	require.NoError(t, err)
	workerCtx, stopWorker := context.WithCancel(context.WithoutCancel(ctx))
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		recoveries.Run(workerCtx, slog.New(slog.DiscardHandler))
	}()
	t.Cleanup(func() {
		stopWorker()
		<-workerDone
	})

	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		nil,
		sessions.Domain{},
		publicURL,
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithURLGrants(grants),
		WithRecovery(recoveries),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)

	signedIn := newBrowser(t, server)
	openLogin(t, signedIn, base, base+"/app")
	require.Equal(t, http.StatusSeeOther, submitLogin(t, signedIn, base, base, rawEmail, oldPassword).status)
	require.Equal(t, http.StatusOK, forwardedCheck(t, signedIn, base, server.Listener.Addr().String(), "/app").status)

	browser := newBrowser(t, server)
	countSessions := func() int64 {
		n, err := queries.CountSessions(ctx)
		require.NoError(t, err)
		return n
	}

	t.Run("the login page links to recovery", func(t *testing.T) {
		page := openLogin(t, browser, base, base+"/app")
		assert.Contains(t, page.body, `href="/recover"`)
	})

	t.Run("a bad origin is refused", func(t *testing.T) {
		resp := submitRecover(t, browser, base, "https://evil.example.test", rawEmail)
		assert.Equal(t, http.StatusForbidden, resp.status)
	})

	var expiredLink string
	t.Run("an unknown address gets the same reply and no mail", func(t *testing.T) {
		unknown := submitRecover(t, browser, base, base, "ghost@example.test")
		known := submitRecover(t, browser, base, base, rawEmail)
		require.Equal(t, http.StatusOK, unknown.status)
		assert.Equal(t, known.status, unknown.status)
		assert.Equal(t, known.body, unknown.body)
		assert.Contains(t, known.body, string(msgRecoverySent))

		// One worker runs the queue in order, so the unknown address was done before this mail.
		mail := mails.next(t)
		assert.Equal(t, email, mail.To)
		assert.Empty(t, mails.mails)
		expiredLink = resetLinkInMail.FindString(string(mail.Body))
		require.NotEmpty(t, expiredLink)
		assert.True(t, strings.HasPrefix(expiredLink, base+"/recover/"))
	})

	t.Run("an expired link is refused", func(t *testing.T) {
		clock.Advance(recovery.LinkLifetime + time.Minute)
		page := get(t, browser, expiredLink)
		assert.Equal(t, http.StatusBadRequest, page.status)
		assert.Contains(t, page.body, string(msgResetLinkInvalid))
		resp := submitReset(t, browser, base, base, tokenOf(expiredLink), newPassword)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.NotZero(t, countSessions())
	})

	var link string
	t.Run("the link opens the new password form", func(t *testing.T) {
		require.Equal(t, http.StatusOK, submitRecover(t, browser, base, base, rawEmail).status)
		link = resetLinkInMail.FindString(string(mails.next(t).Body))
		require.NotEmpty(t, link)

		page := get(t, browser, link)
		require.Equal(t, http.StatusOK, page.status)
		assert.Equal(t, "no-referrer", page.header.Get("Referrer-Policy"))
		assert.Equal(t, "no-store", page.header.Get("Cache-Control"))
		assert.Contains(t, page.body, `name="token" value="`+tokenOf(link)+`"`)
		assert.Contains(t, page.body, `action="/recover/reset"`)
	})

	t.Run("a reset from another origin is refused", func(t *testing.T) {
		resp := submitReset(t, browser, base, "https://evil.example.test", tokenOf(link), newPassword)
		assert.Equal(t, http.StatusForbidden, resp.status)
		assert.NotZero(t, countSessions())
	})

	t.Run("the reset changes the password and ends every session", func(t *testing.T) {
		resp := submitReset(t, browser, base, base, tokenOf(link), newPassword)
		require.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, "no-referrer", resp.header.Get("Referrer-Policy"))
		assert.Contains(t, resp.body, "Password changed")
		assert.Zero(t, countSessions())
		assert.NotEqual(t, http.StatusOK, forwardedCheck(t, signedIn, base, server.Listener.Addr().String(), "/app").status)

		mail := mails.next(t)
		assert.Equal(t, email, mail.To)
		assert.Contains(t, string(mail.Body), base+"/tokens")
		assert.Contains(t, string(mail.Body), "Personal access tokens stay valid")
		assert.NotContains(t, string(mail.Body), newPassword)
	})

	t.Run("the old password stops working and the new one works", func(t *testing.T) {
		fresh := newBrowser(t, server)
		openLogin(t, fresh, base, base+"/app")
		old := submitLogin(t, fresh, base, base, rawEmail, oldPassword)
		require.Equal(t, http.StatusOK, old.status)
		assert.Contains(t, old.body, string(msgWrongCredentials))
		assert.Empty(t, sessionCookies(old))

		resp := submitLogin(t, fresh, base, base, rawEmail, newPassword)
		require.Equal(t, http.StatusSeeOther, resp.status)
		require.Len(t, sessionCookies(resp), 1)
	})

	t.Run("a second use of the link is refused", func(t *testing.T) {
		assert.Equal(t, http.StatusBadRequest, get(t, browser, link).status)
		resp := submitReset(t, browser, base, base, tokenOf(link), oldPassword)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, string(msgResetLinkInvalid))
		assert.Empty(t, mails.mails)
	})

	t.Run("the backoff answers 429", func(t *testing.T) {
		clock.Advance(passwordstep.BackoffWindow + time.Second)
		target := "flood@example.test"
		for range passwordstep.FreeFailures {
			require.Equal(t, http.StatusOK, submitRecover(t, browser, base, base, target).status)
		}
		resp := submitRecover(t, browser, base, base, target)
		assert.Equal(t, http.StatusTooManyRequests, resp.status)
		assert.NotEmpty(t, resp.header.Get("Retry-After"))
	})
}

func TestRecoveryRoutesAnswer503WithoutAMailer(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	for _, path := range []string{"/recover", "/recover/" + strings.Repeat("a", 43)} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, path)
	}
	rec := httptest.NewRecorder()
	(&service{}).renderSteps(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil), http.StatusOK, loginflow.LoginFlow{}, "")
	assert.NotContains(t, rec.Body.String(), `href="/recover"`)
}

func TestLoggedPathHidesTheResetToken(t *testing.T) {
	token := strings.Repeat("a", 43)
	assert.Equal(t, "/recover/{token}", loggedPath("/recover/"+token))
	assert.Equal(t, "/recover/reset", loggedPath("/recover/reset"))
	assert.Equal(t, "/recover", loggedPath("/recover"))
	assert.Equal(t, "/login", loggedPath("/login"))
}

func submitRecover(t *testing.T, browser *http.Client, base, origin, email string) reply {
	t.Helper()
	return submitForm(t, browser, base+"/recover", origin, url.Values{"email": {email}})
}

func submitReset(t *testing.T, browser *http.Client, base, origin, token, password string) reply {
	t.Helper()
	return submitForm(t, browser, base+"/recover/reset", origin, url.Values{"token": {token}, "password": {password}})
}

func submitForm(t *testing.T, browser *http.Client, target, origin string, form url.Values) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	return do(t, browser, req)
}

func tokenOf(link string) string {
	return link[strings.LastIndex(link, "/")+1:]
}
