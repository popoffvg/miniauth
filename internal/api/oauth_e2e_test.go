package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/oauth"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

const oauthTestAdminToken = "bootstrap-token-for-oauth-tests"

// mcpClient is the MCP client side of the flow: its PKCE pair and its callback.
type mcpClient struct {
	id       string
	verifier string
	redirect string
}

func newMCPClient(id, redirect string) mcpClient {
	return mcpClient{id: id, verifier: strings.Repeat("v", 20) + base64.RawURLEncoding.EncodeToString([]byte(redirect))[:23], redirect: redirect}
}

func (c mcpClient) authorizeQuery(resource, state string) url.Values {
	sum := sha256.Sum256([]byte(c.verifier))
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {c.id},
		"redirect_uri":          {c.redirect},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {resource},
	}
}

func TestOAuthEndToEnd(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+6)
	fake := gofakeit.New(fakeSeed + 6)
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
	userPassword, err := users.NewPassword(owner.password)
	require.NoError(t, err)
	created, err := accounts.Create(ctx, login, userPassword)
	require.NoError(t, err)
	owner.id = created.ID

	passwords, err := password.NewService(accountRepo, postgres.NewAttemptRepository(pool))
	require.NoError(t, err)
	accessTokens := tokens.NewService(postgres.NewTokenRepository(pool))
	oauthRepo, err := postgres.NewOAuthRepository(pool)
	require.NoError(t, err)

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host := listener.Addr().String()
	base := "https://" + host
	accessRepo, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	grants := access.NewService(accessRepo, nil)
	mcp := createResource(t, grants, "mcp", host, "/mcp")
	grantResource(t, grants, mcp, access.UserSubject(owner.id))
	oauthServer, err := oauth.NewService(oauthRepo)
	require.NoError(t, err)
	router, err := NewRouter(
		accounts,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		nil,
		sessions.Domain{},
		mustPublicURL(t, base),
		hashToken(t, oauthTestAdminToken),
		&readyState{ok: true},
		slog.New(slog.DiscardHandler),
		WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
		WithAccessTokens(accessTokens),
		WithURLGrants(grants),
		WithOAuth(oauthServer, grants),
	)
	require.NoError(t, err)
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: router}}
	server.StartTLS()
	t.Cleanup(server.Close)

	browser := newBrowser(t, server)
	resource := base + "/mcp"
	var client mcpClient
	var accessToken, refreshToken, oldRefreshToken string

	t.Run("an admin registers the client", func(t *testing.T) {
		resp := adminJSON(t, server.Client(), http.MethodPost, base+oauthClientsPath,
			`{"name":"Claude","redirect_uris":["http://localhost/callback"]}`)
		require.Equal(t, http.StatusCreated, resp.status, resp.body)
		var body struct {
			ClientID string `json:"client_id"`
		}
		require.NoError(t, json.Unmarshal([]byte(resp.body), &body))
		client = newMCPClient(body.ClientID, "http://localhost:43123/callback")
	})

	t.Run("a client with no token learns where the metadata is", func(t *testing.T) {
		resp := mcpCheck(t, server.Client(), base, "", "/mcp/sse")
		require.Equal(t, http.StatusUnauthorized, resp.status)
		assert.Equal(t, `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`, resp.header.Get("WWW-Authenticate"))
	})

	t.Run("the metadata names the resource and this server", func(t *testing.T) {
		resp := forwardedGet(t, server.Client(), base, protectedResourceMetadataPath+"/mcp")
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		assert.JSONEq(t, `{"resource":"`+resource+`","authorization_servers":["`+base+`"],"bearer_methods_supported":["header"]}`, resp.body)

		missing := forwardedGet(t, server.Client(), base, protectedResourceMetadataPath+"/other")
		assert.Equal(t, http.StatusNotFound, missing.status)

		metadataReply := forwardedGet(t, server.Client(), base, authorizationServerMetadataPath)
		require.Equal(t, http.StatusOK, metadataReply.status)
		assert.Contains(t, metadataReply.body, `"token_endpoint":"`+base+`/oauth/token"`)
		assert.Contains(t, metadataReply.body, `"code_challenge_methods_supported":["S256"]`)
	})

	authorizeURL := func(state string) string {
		return base + oauthAuthorizePath + "?" + client.authorizeQuery(resource, state).Encode()
	}

	t.Run("no session sends the browser to the login page and back", func(t *testing.T) {
		resp := get(t, browser, authorizeURL("s1"))
		require.Equal(t, http.StatusSeeOther, resp.status)
		toLogin := mustURL(t, resp.header.Get("Location"))
		assert.Equal(t, "/login", toLogin.Path)
		assert.Equal(t, authorizeURL("s1"), toLogin.Query().Get("return"))
		openLogin(t, browser, base, authorizeURL("s1"))
		loggedIn := submitLogin(t, browser, base, base, owner.login, owner.password)
		require.Equal(t, http.StatusSeeOther, loggedIn.status)
		assert.Equal(t, authorizeURL("s1"), loggedIn.header.Get("Location"))
	})

	t.Run("an unknown redirect URI is a page, not a redirect", func(t *testing.T) {
		query := client.authorizeQuery(resource, "s")
		query.Set("redirect_uri", "https://evil.example.test/cb")
		resp := get(t, browser, base+oauthAuthorizePath+"?"+query.Encode())
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Empty(t, resp.header.Get("Location"))
	})

	t.Run("a resource that is not stored goes back as invalid_target", func(t *testing.T) {
		resp := get(t, browser, base+oauthAuthorizePath+"?"+client.authorizeQuery(base+"/other", "s").Encode())
		require.Equal(t, http.StatusFound, resp.status)
		location := mustURL(t, resp.header.Get("Location"))
		assert.Equal(t, "invalid_target", location.Query().Get("error"))
		assert.Equal(t, "s", location.Query().Get("state"))
	})

	var code string
	t.Run("the user allows the client on the consent page", func(t *testing.T) {
		page := get(t, browser, authorizeURL("s1"))
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "Claude")
		assert.Contains(t, page.body, resource)

		form := client.authorizeQuery(resource, "s1")
		form.Set("action", consentActionAllow)
		cross := postForm(t, browser, base+oauthAuthorizePath, "https://evil.example.test", form)
		assert.Equal(t, http.StatusForbidden, cross.status)

		resp := postForm(t, browser, base+oauthAuthorizePath, base, form)
		require.Equal(t, http.StatusSeeOther, resp.status)
		location := mustURL(t, resp.header.Get("Location"))
		assert.Equal(t, "localhost:43123", location.Host)
		assert.Equal(t, "s1", location.Query().Get("state"))
		assert.Equal(t, base, location.Query().Get("iss"))
		code = location.Query().Get("code")
		require.NotEmpty(t, code)
	})

	t.Run("a wrong verifier does not get a token", func(t *testing.T) {
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantAuthorizationCode}, "client_id": {client.id}, "code": {code},
			"redirect_uri": {client.redirect}, "code_verifier": {strings.Repeat("w", 43)},
		})
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, `"invalid_grant"`)
	})

	t.Run("a mismatched resource in token exchange is rejected", func(t *testing.T) {
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantAuthorizationCode}, "client_id": {client.id}, "code": {code},
			"redirect_uri": {client.redirect}, "code_verifier": {client.verifier},
			"resource": {"https://wrong.example.test/other"},
		})
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, `"invalid_target"`)
	})

	t.Run("the code exchange gives a token that reaches only the resource", func(t *testing.T) {
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantAuthorizationCode}, "client_id": {client.id}, "code": {code},
			"redirect_uri": {client.redirect}, "code_verifier": {client.verifier},
			"resource": {resource},
		})
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		assert.Equal(t, "no-store", resp.header.Get("Cache-Control"))
		accessToken, refreshToken = readTokens(t, resp.body)
		assert.True(t, strings.HasPrefix(accessToken, "idp_"))
		assert.True(t, strings.HasPrefix(refreshToken, "idr_"))

		assert.Equal(t, http.StatusOK, mcpCheck(t, server.Client(), base, accessToken, "/mcp/sse").status)
		assert.Equal(t, http.StatusForbidden, mcpCheck(t, server.Client(), base, accessToken, "/other").status)
		assert.Equal(t, http.StatusUnauthorized, mcpCheck(t, server.Client(), base, refreshToken, "/mcp").status)
		assert.Empty(t, listTokens(t, accessTokens, owner.id), "the token page MUST NOT list an OAuth token")
	})

	t.Run("a refresh rotates both tokens", func(t *testing.T) {
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantRefreshToken}, "client_id": {client.id}, "refresh_token": {refreshToken},
		})
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		newAccess, newRefresh := readTokens(t, resp.body)
		assert.NotEqual(t, refreshToken, newRefresh)
		assert.Equal(t, http.StatusOK, mcpCheck(t, server.Client(), base, newAccess, "/mcp").status)
		accessToken, refreshToken, oldRefreshToken = newAccess, newRefresh, refreshToken
	})

	t.Run("a refresh token used twice ends the consent", func(t *testing.T) {
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantRefreshToken}, "client_id": {client.id}, "refresh_token": {oldRefreshToken},
		})
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, `"invalid_grant"`)
		assert.Equal(t, http.StatusUnauthorized, mcpCheck(t, server.Client(), base, accessToken, "/mcp").status)
		again := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantRefreshToken}, "client_id": {client.id}, "refresh_token": {refreshToken},
		})
		assert.Equal(t, http.StatusBadRequest, again.status)
	})

	t.Run("a code used twice is refused", func(t *testing.T) {
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantAuthorizationCode}, "client_id": {client.id}, "code": {code},
			"redirect_uri": {client.redirect}, "code_verifier": {client.verifier},
		})
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Contains(t, resp.body, `"invalid_grant"`)
	})

	t.Run("after the consent ends the page asks again, then it is remembered", func(t *testing.T) {
		page := get(t, browser, authorizeURL("s2"))
		require.Equal(t, http.StatusOK, page.status)
		form := client.authorizeQuery(resource, "s2")
		form.Set("action", consentActionAllow)
		require.Equal(t, http.StatusSeeOther, postForm(t, browser, base+oauthAuthorizePath, base, form).status)

		remembered := get(t, browser, authorizeURL("s3"))
		require.Equal(t, http.StatusFound, remembered.status)
		location := mustURL(t, remembered.header.Get("Location"))
		assert.NotEmpty(t, location.Query().Get("code"))
		resp := tokenRequestFor(t, server.Client(), base, url.Values{
			"grant_type": {grantAuthorizationCode}, "client_id": {client.id}, "code": {location.Query().Get("code")},
			"redirect_uri": {client.redirect}, "code_verifier": {client.verifier},
		})
		require.Equal(t, http.StatusOK, resp.status, resp.body)
		accessToken, _ = readTokens(t, resp.body)
	})

	t.Run("deny sends access_denied", func(t *testing.T) {
		form := client.authorizeQuery(resource, "s4")
		form.Set("action", consentActionDeny)
		resp := postForm(t, browser, base+oauthAuthorizePath, base, form)
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, "access_denied", mustURL(t, resp.header.Get("Location")).Query().Get("error"))
	})

	t.Run("the user disconnects the app on the token page", func(t *testing.T) {
		page := get(t, browser, base+tokensPath)
		require.Equal(t, http.StatusOK, page.status)
		assert.Contains(t, page.body, "Connected apps")
		start := strings.Index(page.body, `action="`+consentsPath+"/")
		require.GreaterOrEqual(t, start, 0)
		action, _, found := strings.Cut(page.body[start+len(`action="`):], `"`)
		require.True(t, found)
		resp := postForm(t, browser, base+action, base, url.Values{})
		require.Equal(t, http.StatusSeeOther, resp.status)
		assert.Equal(t, base+"/tokens?done=consent-revoked", resp.header.Get("Location"))
		assert.Equal(t, http.StatusUnauthorized, mcpCheck(t, server.Client(), base, accessToken, "/mcp").status)
	})

	t.Run("an admin deletes the client", func(t *testing.T) {
		resp := adminJSON(t, server.Client(), http.MethodDelete, base+oauthClientsPath+"/"+client.id, "")
		assert.Equal(t, http.StatusNoContent, resp.status)
		gone := get(t, browser, authorizeURL("s5"))
		assert.Equal(t, http.StatusBadRequest, gone.status)
	})
}

func adminJSON(t *testing.T, httpClient *http.Client, method, target, body string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+oauthTestAdminToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return do(t, httpClient, req)
}

// mcpCheck is /auth/check as the proxy sends it for an MCP client. An empty token sends no Authorization.
func mcpCheck(t *testing.T, httpClient *http.Client, base, token, uri string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/auth/check", nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", strings.TrimPrefix(base, "https://"))
	req.Header.Set("X-Forwarded-Uri", uri)
	return do(t, httpClient, req)
}

func forwardedGet(t *testing.T, httpClient *http.Client, base, path string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+path, nil)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", strings.TrimPrefix(base, "https://"))
	return do(t, httpClient, req)
}

func tokenRequestFor(t *testing.T, httpClient *http.Client, base string, form url.Values) reply {
	t.Helper()
	return postForm(t, httpClient, base+oauthTokenPath, "", form)
}

func readTokens(t *testing.T, body string) (string, string) {
	t.Helper()
	var tokenReply tokenResponse
	require.NoError(t, json.Unmarshal([]byte(body), &tokenReply))
	assert.Equal(t, "Bearer", tokenReply.TokenType)
	assert.Equal(t, int64(3600), tokenReply.ExpiresIn)
	return tokenReply.AccessToken, tokenReply.RefreshToken
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}
