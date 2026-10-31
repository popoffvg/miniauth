package api

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/telegramstep"
	"github.com/popoffvg/miniauth/internal/telegramstep/telegramtest"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestTelegramLoginEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+5)
	fake := gofakeit.New(fakeSeed + 5)
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

	botName, err := telegramstep.ParseBotName(telegramtest.BotName)
	require.NoError(t, err)
	step, err := telegramstep.NewStep(telegramstep.Config{
		BotName:  botName,
		BotToken: telegramstep.ParseBotToken(telegramtest.BotToken),
	}, accountRepo, postgres.NewTelegramProofRepository(pool))
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, nil)
	app := createResource(t, grants, "app", server.Listener.Addr().String(), "/app")
	grantResource(t, grants, app, access.UserSubject(account.ID))
	logs := &lockedBuffer{}
	flowStore := postgres.NewFlowStore(pool)
	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		nil,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.NewJSONHandler(logs, nil)),
		WithLogin(loginflow.NewLoginFlows(flowStore), passwords),
		WithTelegram(step, identitylink.NewService(postgres.NewIdentityLinkRepository(pool))),
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
	linked := func(subject string) bool {
		_, err := queries.GetExternalIdentity(ctx, sqlcgen.GetExternalIdentityParams{
			Kind:    string(users.KindTelegram),
			Subject: pgtype.Text{String: subject, Valid: true},
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return false
		}
		require.NoError(t, err)
		return true
	}
	var usedHashes []string
	callback := func(browser *http.Client, query url.Values) reply {
		usedHashes = append(usedHashes, query.Get("hash"))
		return get(t, browser, base+TelegramCallbackPath+"?"+query.Encode())
	}
	signed := func(userID int64, authDate time.Time) url.Values {
		return telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(userID, authDate))
	}

	t.Run("the login page shows the widget with a CSP for telegram.org only", func(t *testing.T) {
		page := openLogin(t, newBrowser(t, server), base, base+"/app")
		assert.Contains(t, page.body, `src="https://telegram.org/js/telegram-widget.js?22"`)
		assert.Contains(t, page.body, `data-telegram-login="`+telegramtest.BotName+`"`)
		assert.Contains(t, page.body, `data-auth-url="`+base+TelegramCallbackPath+`"`)
		assert.Equal(t, telegramPageCSP, page.header.Get("Content-Security-Policy"))
	})

	t.Run("a forged hash is refused", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		forged := telegramtest.Sign("987654321:not-the-bot-token", telegramtest.Fields(1001, time.Now()))
		resp := callback(browser, forged)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, string(msgTelegramFailed))
		assert.Empty(t, sessionCookies(resp))
		assert.Zero(t, countSessions())
		assert.Zero(t, countPending())
	})

	t.Run("an old auth_date is refused", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		resp := callback(browser, signed(1001, time.Now().Add(-telegramstep.MaxAge-time.Minute)))
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, string(msgTelegramFailed))
		assert.Empty(t, sessionCookies(resp))
		assert.Zero(t, countPending())
	})

	t.Run("a callback with no open flow is refused", func(t *testing.T) {
		resp := callback(newBrowser(t, server), signed(1001, time.Now()))
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, string(msgFlowExpired))
		assert.Empty(t, sessionCookies(resp))
		assert.Zero(t, countPending())
	})

	unknownData := signed(1001, time.Now().Add(-time.Minute))

	t.Run("an unknown id starts no session, then a password login links it", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		resp := callback(browser, unknownData)
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, string(msgLinkTelegram))
		assert.Contains(t, resp.body, `name="password"`)
		assert.Empty(t, sessionCookies(resp))
		assert.Zero(t, countSessions())
		assert.Equal(t, int64(1), countPending())
		assert.False(t, linked("1001"))
		count, err := queries.CountUsers(t.Context())
		require.NoError(t, err)
		assert.Equal(t, int64(1), count, "an unknown id creates no user")

		login := submitLogin(t, browser, base, base, rawLogin, rawPassword)
		require.Equal(t, http.StatusSeeOther, login.status)
		confirmPage := base + linkPagePath + "?return=" + url.QueryEscape(base+"/app")
		assert.Equal(t, confirmPage, login.header.Get("Location"))
		require.Len(t, sessionCookies(login), 1)
		assert.False(t, linked("1001"), "a password login alone MUST NOT link")

		page := get(t, browser, confirmPage)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "Telegram account 1001")
		assert.Contains(t, page.body, rawLogin)

		refused := confirmLink(t, browser, base, "https://evil.example.test", "link", base+"/app")
		assert.Equal(t, http.StatusForbidden, refused.status)
		assert.False(t, linked("1001"))

		done := confirmLink(t, browser, base, base, "link", base+"/app")
		require.Equal(t, http.StatusSeeOther, done.status, done.body)
		assert.Equal(t, base+"/app", done.header.Get("Location"))
		assert.Zero(t, countPending())
		assert.True(t, linked("1001"))
	})

	t.Run("a replay of used data is refused in another browser", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		before := countSessions()
		resp := callback(browser, unknownData)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, string(msgTelegramFailed))
		assert.Empty(t, sessionCookies(resp))
		assert.Equal(t, before, countSessions())
	})

	t.Run("a linked account signs in with Telegram alone", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app/telegram")
		before := countSessions()
		resp := callback(browser, signed(1001, time.Now()))
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+"/app/telegram", resp.header.Get("Location"))
		require.Len(t, sessionCookies(resp), 1)
		assert.Equal(t, before+1, countSessions())

		check := forwardedCheck(t, browser, base, server.Listener.Addr().String(), "/app/telegram")
		require.Equal(t, http.StatusOK, check.status)
		assert.Equal(t, rawLogin, check.header.Get(headerAuthUser))
		assert.Equal(t, "telegram", check.header.Get(headerAuthMethod))
	})

	t.Run("the log holds no widget hash", func(t *testing.T) {
		browser := newBrowser(t, server)
		openLogin(t, browser, base, base+"/app")
		query := signed(1002, time.Now())
		usedHashes = append(usedHashes, query.Get("hash"))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+TelegramCallbackPath+"?"+query.Encode(), nil)
		require.NoError(t, err)
		req.Header.Set("X-Request-ID", query.Get("hash"))
		do(t, browser, req)

		written := logs.String()
		assert.Contains(t, written, TelegramCallbackPath)
		for _, hash := range usedHashes {
			assert.NotContains(t, written, hash)
		}
	})
}
