package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 uses HMAC-SHA-1. The test computes codes on its own.
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/totpstep"
	"github.com/popoffvg/miniauth/internal/users"
)

var (
	totpSecretPattern   = regexp.MustCompile(`id="totp-secret">([A-Z2-7]{32})<`)
	recoveryCodePattern = regexp.MustCompile(`<code>([a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4})</code>`)
	totpFormSentinel    = `action="/login/totp"`
)

func TestTwoStepLoginEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+5)
	fake := gofakeit.New(fakeSeed + 5)
	owner := &account{login: fake.Regex(`[a-z][a-z0-9]{7}`), password: fake.Password(true, true, true, true, false, 24)}

	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	accountRepo := postgres.NewUserRepository(pool)
	accounts := users.NewService(accountRepo)
	login, err := users.ParseLogin(owner.login)
	require.NoError(t, err)
	password, err := users.NewPassword(owner.password)
	require.NoError(t, err)
	user, err := accounts.Create(ctx, login, password)
	require.NoError(t, err)
	owner.id = user.ID

	// The fake clock runs one hour behind, so a TOTP failure at a fake time
	// is outside the backoff window of the password step, which reads the real clock.
	clock := &testClock{now: time.Now().Add(-time.Hour)}
	attempts := postgres.NewAttemptRepository(pool)
	totpRepo := postgres.NewTOTPRepository(pool)
	totp, err := totpstep.NewServiceWithClock(totpRepo, attempts, randomTOTPKey(t), clock.Now)
	require.NoError(t, err)
	passwords, err := passwordstep.NewService(accountRepo, attempts, passwordstep.WithSecondFactors(totp))
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
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
		WithTOTP(totp),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)

	devicesPage := base + sessionsPagePath
	owned := newBrowser(t, server)
	var secret string
	var recoveryCodes []string

	// passwordOnly signs a new browser in with the password and returns the browser and the reply.
	passwordOnly := func(t *testing.T) (*http.Client, reply) {
		t.Helper()
		browser := newBrowser(t, server)
		openLogin(t, browser, base, devicesPage)
		return browser, submitLogin(t, browser, base, base, owner.login, owner.password)
	}
	assertSignedIn := func(t *testing.T, resp reply) {
		t.Helper()
		require.Equal(t, http.StatusSeeOther, resp.status, resp.body)
		assert.Equal(t, devicesPage, resp.header.Get("Location"))
		assert.NotEmpty(t, sessionCookies(resp))
	}
	assertNotSignedIn := func(t *testing.T, browser *http.Client, resp reply) {
		t.Helper()
		assert.Empty(t, sessionCookies(resp))
		page := get(t, browser, devicesPage)
		assert.Equal(t, http.StatusFound, page.status)
	}

	t.Run("before enrollment a password opens a session", func(t *testing.T) {
		openLogin(t, owned, base, devicesPage)
		assertSignedIn(t, submitLogin(t, owned, base, base, owner.login, owner.password))
		page := get(t, owned, devicesPage)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "Two-step login: off")
		assert.Contains(t, page.body, `action="/sessions/totp/enroll"`)
	})

	t.Run("an old login asks for a step-up before enrollment", func(t *testing.T) {
		clock.Advance(sessions.StepUpAfter + time.Minute)
		resp := postForm(t, owned, base+totpEnrollPath, base, url.Values{})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, stepUpFormSentinel)
		assert.NotContains(t, resp.body, "totp-secret")

		up := submitStepUp(t, owned, base, "", owner.password)
		require.Equal(t, http.StatusSeeOther, up.status)
		assert.Equal(t, devicesPage, up.header.Get("Location"))
	})

	t.Run("enrollment shows the secret as a QR code and as text", func(t *testing.T) {
		resp := postForm(t, owned, base+totpEnrollPath, base, url.Values{})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, "no-store", resp.header.Get("Cache-Control"))
		assert.Contains(t, resp.body, "<svg")
		match := totpSecretPattern.FindStringSubmatch(resp.body)
		require.Len(t, match, 2)
		secret = match[1]

		stored, err := totpRepo.Find(t.Context(), owner.id)
		require.NoError(t, err)
		assert.False(t, stored.Confirmed())
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		require.NoError(t, err)
		assert.False(t, bytes.Contains(stored.Sealed, raw), "the database holds the clear secret")
		assert.NotContains(t, string(stored.Sealed), secret)
	})

	t.Run("a wrong code does not turn on two-step login", func(t *testing.T) {
		require.NotEmpty(t, secret)
		wrong := totpCode(t, secret, clock.Now().Add(10*totpstep.Period))
		resp := postForm(t, owned, base+totpConfirmPath, base, url.Values{"code": {wrong}})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, string(msgWrongCode))
		assert.Contains(t, resp.body, secret)
		assert.Contains(t, get(t, owned, devicesPage).body, "Two-step login: off")
	})

	t.Run("the confirming code turns on two-step login and shows the recovery codes once", func(t *testing.T) {
		require.NotEmpty(t, secret)
		resp := postForm(t, owned, base+totpConfirmPath, base, url.Values{"code": {totpCode(t, secret, clock.Now())}})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, "no-store", resp.header.Get("Cache-Control"))
		for _, match := range recoveryCodePattern.FindAllStringSubmatch(resp.body, -1) {
			recoveryCodes = append(recoveryCodes, match[1])
		}
		require.Len(t, recoveryCodes, totpstep.RecoveryCodeCount)

		page := get(t, owned, devicesPage)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "Two-step login: on")
		assert.Contains(t, page.body, `action="/sessions/totp/disable"`)
		assert.NotContains(t, page.body, recoveryCodes[0])
		assert.NotContains(t, page.body, secret)
	})

	t.Run("a password alone does not open a session", func(t *testing.T) {
		require.NotEmpty(t, secret)
		browser, resp := passwordOnly(t)
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, totpFormSentinel)
		assert.Contains(t, resp.body, `href="/login/recovery-code"`)
		assertNotSignedIn(t, browser, resp)
	})

	t.Run("password and TOTP open a session", func(t *testing.T) {
		require.NotEmpty(t, secret)
		// The confirming code used the current step.
		clock.Advance(totpstep.Period)
		browser, resp := passwordOnly(t)
		require.Contains(t, resp.body, totpFormSentinel)
		code := totpCode(t, secret, clock.Now())
		assertSignedIn(t, postForm(t, browser, base+loginTOTPPath, base, url.Values{"code": {code}}))
		assert.Equal(t, http.StatusOK, get(t, browser, devicesPage).status)
	})

	t.Run("a TOTP code is accepted once", func(t *testing.T) {
		require.NotEmpty(t, secret)
		browser, resp := passwordOnly(t)
		require.Contains(t, resp.body, totpFormSentinel)
		for _, at := range []time.Time{clock.Now(), clock.Now().Add(-totpstep.Period)} {
			again := postForm(t, browser, base+loginTOTPPath, base, url.Values{"code": {totpCode(t, secret, at)}})
			require.Equal(t, http.StatusOK, again.status)
			assert.Contains(t, again.body, string(msgWrongCode))
			assertNotSignedIn(t, browser, again)
		}
	})

	t.Run("a recovery code works once", func(t *testing.T) {
		require.Len(t, recoveryCodes, totpstep.RecoveryCodeCount)
		browser, _ := passwordOnly(t)
		form := get(t, browser, base+loginRecoveryCodePath)
		require.Equal(t, http.StatusOK, form.status)
		assert.Contains(t, form.body, `action="/login/recovery-code"`)
		assertSignedIn(t, postForm(t, browser, base+loginRecoveryCodePath, base, url.Values{"code": {recoveryCodes[0]}}))

		other, _ := passwordOnly(t)
		again := postForm(t, other, base+loginRecoveryCodePath, base, url.Values{"code": {recoveryCodes[0]}})
		require.Equal(t, http.StatusOK, again.status)
		assert.Contains(t, again.body, string(msgWrongCode))
		assertNotSignedIn(t, other, again)

		assertSignedIn(t, postForm(t, other, base+loginRecoveryCodePath, base, url.Values{"code": {recoveryCodes[1]}}))
	})

	t.Run("wrong codes start the backoff of the second factor", func(t *testing.T) {
		require.NotEmpty(t, secret)
		// The earlier failures leave the backoff window.
		clock.Advance(passwordstep.BackoffWindow + time.Minute)
		browser, resp := passwordOnly(t)
		require.Contains(t, resp.body, totpFormSentinel)
		wrong := totpCode(t, secret, clock.Now().Add(10*totpstep.Period))
		for range passwordstep.FreeFailures {
			failed := postForm(t, browser, base+loginTOTPPath, base, url.Values{"code": {wrong}})
			require.Equal(t, http.StatusOK, failed.status)
		}
		right := totpCode(t, secret, clock.Now())
		blocked := postForm(t, browser, base+loginTOTPPath, base, url.Values{"code": {right}})
		require.Equal(t, http.StatusTooManyRequests, blocked.status)
		assert.NotEmpty(t, blocked.header.Get("Retry-After"))
		assertNotSignedIn(t, browser, blocked)

		clock.Advance(passwordstep.MaxDelay)
		assertSignedIn(t, postForm(t, browser, base+loginTOTPPath, base, url.Values{"code": {totpCode(t, secret, clock.Now())}}))
	})

	t.Run("turning off two-step login needs a step-up", func(t *testing.T) {
		resp := postForm(t, owned, base+totpDisablePath, base, url.Values{})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, stepUpFormSentinel)
		require.Equal(t, http.StatusSeeOther, submitStepUp(t, owned, base, "", owner.password).status)

		off := postForm(t, owned, base+totpDisablePath, base, url.Values{})
		require.Equal(t, http.StatusSeeOther, off.status)
		assert.Contains(t, get(t, owned, devicesPage).body, "Two-step login: off")

		_, resp = passwordOnly(t)
		assertSignedIn(t, resp)
	})
}

// totpCode is the RFC 6238 code of the base32 secret at at: HMAC-SHA-1, 6 digits, 30 s.
func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30)) //nolint:gosec // The test clock is after 1970.
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

func randomTOTPKey(t *testing.T) totpstep.Key {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	key, err := totpstep.ParseKey(base64.StdEncoding.EncodeToString(raw))
	require.NoError(t, err)
	return key
}
