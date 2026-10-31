package api

import (
	"bytes"
	"encoding/json"
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
	"github.com/popoffvg/miniauth/internal/passkeystep"
	"github.com/popoffvg/miniauth/internal/passkeystep/passkeytest"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

var passkeyDeletePattern = regexp.MustCompile(`action="/passkeys/([0-9a-f-]{36})/delete"`)

// The relying party id is the cookie domain. The server listens on 127.0.0.1, which is the origin.
const passkeyParty = "example.test"

func TestPasskeyEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+5)
	fake := gofakeit.New(fakeSeed + 5)
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
	clock := &testClock{now: time.Now()}
	domain, err := sessions.ParseDomain("." + passkeyParty)
	require.NoError(t, err)

	server := httptest.NewUnstartedServer(nil)
	base := "https://" + server.Listener.Addr().String()
	// The server listens on an IP address, which a browser never accepts with this id.
	// The test authenticator does not check the pair, so the party is built without NewRelyingParty.
	party := passkeystep.RelyingParty{ID: passkeyParty, Origin: passkeystep.Origin(base)}
	flowStore := postgres.NewFlowStore(pool)
	passkeys, err := passkeystep.NewService(party, postgres.NewPasskeyRepository(pool), flowStore)
	require.NoError(t, err)
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, nil)
	app := createResource(t, grants, "app", "app."+passkeyParty, "/app")
	grantResource(t, grants, app, access.UserSubject(owner.id))
	router, err := NewRouter(
		accounts,
		sessions.NewServiceWithClock(postgres.NewSessionRepository(pool), clock.Now),
		nil,
		domain,
		mustPublicURL(t, base),
		hashToken(t, "bootstrap-token-for-tests"),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(flowStore), passwords),
		WithPasskeys(passkeys),
		WithURLGrants(grants),
	)
	require.NoError(t, err)
	server.Config.Handler = router
	server.StartTLS()
	t.Cleanup(server.Close)

	ownerBrowser := newPasskeyBrowser(t, server)
	key := passkeytest.New(t, passkeyParty, base)
	ownerHandle := owner.id.Bytes()
	var firstAssertion []byte

	t.Run("the login page offers a passkey with the one script", func(t *testing.T) {
		page := openLogin(t, newPasskeyBrowser(t, server), base, base+"/")
		assert.Contains(t, page.body, "Sign in with a passkey")
		assert.Contains(t, page.body, `data-passkey-login="`+passkeyLoginPath+`"`)
		assert.Contains(t, page.body, `<script src="`+passkeyScriptPath+`"></script>`)
		assert.Equal(t, scriptPageCSP, page.header.Get("Content-Security-Policy"))
		assert.Equal(t, 1, strings.Count(page.body, "<script"))

		script := get(t, newPasskeyBrowser(t, server), base+passkeyScriptPath)
		require.Equal(t, http.StatusOK, script.status)
		assert.Contains(t, script.header.Get("Content-Type"), "text/javascript")
		assert.Contains(t, script.body, "navigator.credentials.get")
		assert.Contains(t, script.body, "navigator.credentials.create")
	})

	t.Run("a signed-in user adds a passkey", func(t *testing.T) {
		passwordLogin(t, ownerBrowser, base, owner)
		page := get(t, ownerBrowser, base+passkeyNewPath)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, `data-passkey-add="`+passkeysPath+`"`)
		assert.Equal(t, scriptPageCSP, page.header.Get("Content-Security-Policy"))

		options := postJSON(t, ownerBrowser, base+passkeysPath+"/options", base, []byte(`{}`))
		require.Equal(t, http.StatusOK, options.status, options.body)
		creation := decodeOptions(t, options.body)
		assert.Equal(t, passkeyParty, creation.PublicKey.RP.ID)
		assert.Equal(t, "required", creation.PublicKey.AuthenticatorSelection.ResidentKey)
		assert.Equal(t, "required", creation.PublicKey.AuthenticatorSelection.UserVerification)
		assert.Equal(t, ownerHandle[:], passkeytest.Challenge(t, creation.PublicKey.User.ID))

		added := postJSON(t, ownerBrowser, base+passkeysPath, base, addBody(t, "laptop", key.Create(t, passkeytest.Challenge(t, creation.PublicKey.Challenge))))
		require.Equal(t, http.StatusCreated, added.status, added.body)
		assert.JSONEq(t, `{"location":"`+base+sessionsPagePath+`"}`, added.body)

		list := get(t, ownerBrowser, base+sessionsPagePath)
		require.Equal(t, http.StatusOK, list.status)
		assert.Contains(t, list.body, "laptop")
		assert.Contains(t, list.body, `data-label="Last used"><span class="subtle">Never</span>`)
		assert.NotContains(t, list.body, "<script")
		assert.Regexp(t, passkeyDeletePattern, list.body)
	})

	t.Run("a passkey alone opens a session with two factors", func(t *testing.T) {
		browser := newPasskeyBrowser(t, server)
		challenge := beginPasskeyLogin(t, browser, base)
		firstAssertion = key.Get(t, challenge, ownerHandle[:])
		resp := postJSON(t, browser, base+passkeyLoginPath, base, firstAssertion)
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		assert.JSONEq(t, `{"location":"`+base+`/"}`, resp.body)
		session := sessionCookies(resp)
		require.Len(t, session, 1)

		check := forwardedCheckWithSession(t, browser, base, "app."+passkeyParty, "/app", session[0])
		require.Equal(t, http.StatusOK, check.status)
		assert.Equal(t, owner.login, check.header.Get(headerAuthUser))
		assert.Equal(t, "passkey", check.header.Get(headerAuthMethod))

		id, err := sessions.ParseID(session[0].Value)
		require.NoError(t, err)
		opened, _, err := sessions.NewService(postgres.NewSessionRepository(pool)).Open(t.Context(), id)
		require.NoError(t, err)
		assert.Equal(t, loginflow.Factors(loginflow.FactorPasskey), opened.Factors)
		withSecondFactor, err := loginflow.LoginFlow{State: loginflow.StateAwaiting, NeedsSecond: true}.Next(loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorPasskey, UserID: owner.id})
		require.NoError(t, err)
		assert.Equal(t, loginflow.StateComplete, withSecondFactor.State)
	})

	t.Run("a response without user verification is refused", func(t *testing.T) {
		browser := newPasskeyBrowser(t, server)
		challenge := beginPasskeyLogin(t, browser, base)
		key.SkipUserVerification = true
		resp := postJSON(t, browser, base+passkeyLoginPath, base, key.Get(t, challenge, ownerHandle[:]))
		key.SkipUserVerification = false
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, msgPasskeyRefused)
		assert.Empty(t, sessionCookies(resp))

		t.Run("and its challenge is used", func(t *testing.T) {
			again := postJSON(t, browser, base+passkeyLoginPath, base, key.Get(t, challenge, ownerHandle[:]))
			assert.Equal(t, http.StatusBadRequest, again.status)
			assert.Empty(t, sessionCookies(again))
		})
	})

	t.Run("a replayed assertion is refused", func(t *testing.T) {
		require.NotEmpty(t, firstAssertion)
		browser := newPasskeyBrowser(t, server)
		beginPasskeyLogin(t, browser, base)
		resp := postJSON(t, browser, base+passkeyLoginPath, base, firstAssertion)
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Empty(t, sessionCookies(resp))
	})

	t.Run("a counter that goes back is refused", func(t *testing.T) {
		browser := newPasskeyBrowser(t, server)
		challenge := beginPasskeyLogin(t, browser, base)
		key.SignCount = 0
		resp := postJSON(t, browser, base+passkeyLoginPath, base, key.Get(t, challenge, ownerHandle[:]))
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Empty(t, sessionCookies(resp))
		key.SignCount = 100
	})

	t.Run("a bad origin is refused", func(t *testing.T) {
		browser := newPasskeyBrowser(t, server)
		openLogin(t, browser, base, base+"/")
		for _, bad := range []string{"", "https://evil.example.test"} {
			assert.Equal(t, http.StatusForbidden, postJSON(t, browser, base+passkeyLoginPath+"/options", bad, []byte(`{}`)).status, bad)
			assert.Equal(t, http.StatusForbidden, postJSON(t, ownerBrowser, base+passkeysPath+"/options", bad, []byte(`{}`)).status, bad)
		}
	})

	var passkeyID string
	t.Run("another user cannot delete the passkey", func(t *testing.T) {
		list := get(t, ownerBrowser, base+sessionsPagePath)
		matches := passkeyDeletePattern.FindStringSubmatch(list.body)
		require.Len(t, matches, 2)
		passkeyID = matches[1]

		otherBrowser := newPasskeyBrowser(t, server)
		passwordLogin(t, otherBrowser, base, other)
		resp := postForm(t, otherBrowser, base+passkeysPath+"/"+passkeyID+"/delete", base, url.Values{})
		assert.Equal(t, http.StatusNotFound, resp.status)
		assert.Contains(t, resp.body, string(msgPasskeyNotFound))
		assert.Len(t, listPasskeys(t, passkeys, owner.id), 1)

		crossSite := postForm(t, ownerBrowser, base+passkeysPath+"/"+passkeyID+"/delete", "https://evil.example.test", url.Values{})
		assert.Equal(t, http.StatusForbidden, crossSite.status)
		assert.Len(t, listPasskeys(t, passkeys, owner.id), 1)
	})

	t.Run("an old login asks for a step-up before a change", func(t *testing.T) {
		require.NotEmpty(t, passkeyID)
		clock.Advance(sessions.StepUpAfter + time.Minute)
		options := postJSON(t, ownerBrowser, base+passkeysPath+"/options", base, []byte(`{}`))
		assert.Equal(t, http.StatusForbidden, options.status)

		resp := postForm(t, ownerBrowser, base+passkeysPath+"/"+passkeyID+"/delete", base, url.Values{})
		require.Equal(t, http.StatusOK, resp.status)
		assert.Contains(t, resp.body, stepUpFormSentinel)
		assert.Len(t, listPasskeys(t, passkeys, owner.id), 1)

		confirmed := submitStepUp(t, ownerBrowser, base, "", owner.password)
		require.Equal(t, http.StatusSeeOther, confirmed.status)
		assert.Equal(t, base+sessionsPagePath, confirmed.header.Get("Location"))
	})

	t.Run("the owner deletes the passkey", func(t *testing.T) {
		resp := postForm(t, ownerBrowser, base+passkeysPath+"/"+passkeyID+"/delete", base, url.Values{})
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+withDone(sessionsPagePath, donePasskeyDeleted), resp.header.Get("Location"))
		assert.Empty(t, listPasskeys(t, passkeys, owner.id))

		browser := newPasskeyBrowser(t, server)
		challenge := beginPasskeyLogin(t, browser, base)
		login := postJSON(t, browser, base+passkeyLoginPath, base, key.Get(t, challenge, ownerHandle[:]))
		assert.Equal(t, http.StatusBadRequest, login.status)
	})
}

// webauthnOptions is the part of the options JSON the test reads.
type webauthnOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
		UserVerification string `json:"userVerification"`
	} `json:"publicKey"`
}

func decodeOptions(t *testing.T, body string) webauthnOptions {
	t.Helper()
	var options webauthnOptions
	require.NoError(t, json.Unmarshal([]byte(body), &options))
	require.NotEmpty(t, options.PublicKey.Challenge)
	return options
}

// beginPasskeyLogin opens the login page and returns the challenge of the passkey step.
func beginPasskeyLogin(t *testing.T, browser *http.Client, base string) []byte {
	t.Helper()
	openLogin(t, browser, base, base+"/")
	resp := postJSON(t, browser, base+passkeyLoginPath+"/options", base, []byte(`{}`))
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	options := decodeOptions(t, resp.body)
	assert.Equal(t, "required", options.PublicKey.UserVerification)
	return passkeytest.Challenge(t, options.PublicKey.Challenge)
}

func passwordLogin(t *testing.T, browser *http.Client, base string, a *account) {
	t.Helper()
	openLogin(t, browser, base, base+"/")
	resp := submitLogin(t, browser, base, base, a.login, a.password)
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Len(t, sessionCookies(resp), 1)
}

func addBody(t *testing.T, name string, credential []byte) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "credential": json.RawMessage(credential)})
	require.NoError(t, err)
	return body
}

func postJSON(t *testing.T, browser *http.Client, target, origin string, body []byte) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return do(t, browser, req)
}

func listPasskeys(t *testing.T, passkeys *passkeystep.Service, userID users.ID) []passkeystep.Passkey {
	t.Helper()
	list, err := passkeys.List(t.Context(), userID)
	require.NoError(t, err)
	return list
}

// newPasskeyBrowser keeps cookies by name for every host.
// The session cookie has Domain=example.test, and a standard jar drops it for the 127.0.0.1 server.
func newPasskeyBrowser(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	client := newBrowser(t, server)
	client.Jar = &anyHostJar{cookies: map[string]*http.Cookie{}}
	return client
}

type anyHostJar struct {
	mu      sync.Mutex
	cookies map[string]*http.Cookie
}

func (j *anyHostJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, cookie := range cookies {
		if cookie.MaxAge < 0 {
			delete(j.cookies, cookie.Name)
			continue
		}
		j.cookies[cookie.Name] = cookie
	}
}

func (j *anyHostJar) Cookies(*url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]*http.Cookie, 0, len(j.cookies))
	for _, cookie := range j.cookies {
		out = append(out, &http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	return out
}
