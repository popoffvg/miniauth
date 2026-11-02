package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/access/accesstest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

const mcpResourceMetadata = `resource_metadata="https://id.example.test/.well-known/oauth-protected-resource/mcp"`

// mcpFixture is a router with three resources: mcp on the miniauth host, app with a grant, and other with no grant.
type mcpFixture struct {
	router http.Handler
	issuer *tokens.Service
	user   users.User
}

func newMCPFixture(t *testing.T, grantMCP bool) mcpFixture {
	t.Helper()
	accounts := &memRepo{}
	user := users.User{ID: users.NewID(), Login: mustLogin(t, "ada@example.test"), CreatedAt: time.Now().UTC()}
	accounts.put(user)
	issuer := tokens.NewService(newMemTokens())
	grants := access.NewService(accesstest.NewRepository(), nil)
	mcpResource := createResource(t, grants, "mcp", "id.example.test", "/mcp")
	app := createResource(t, grants, "app", "app.example.test", "/api/")
	createResource(t, grants, "other", "other.example.test", "/")
	if grantMCP {
		grantResource(t, grants, mcpResource, access.UserSubject(user.ID))
	}
	grantResource(t, grants, app, access.UserSubject(user.ID))
	router, err := NewRouter(users.NewService(accounts), sessions.NewService(newMemSessions()), newMemGroups(), mustDomain(t, ".example.test"), mustPublicURL(t, "https://id.example.test"), hashToken(t, "bootstrap-token-for-tests"), &readyState{ok: true}, slog.New(slog.DiscardHandler), WithAccessTokens(issuer), WithURLGrants(grants), WithAccessAdmin(grants))
	require.NoError(t, err)
	return mcpFixture{router: router, issuer: issuer, user: user}
}

func (f mcpFixture) issue(t *testing.T, rawScopes ...string) string {
	t.Helper()
	scopes, err := tokens.ParseScopes(rawScopes)
	require.NoError(t, err)
	name, err := tokens.ParseName("agent")
	require.NoError(t, err)
	secret, _, err := f.issuer.Issue(t.Context(), f.user.ID, name, scopes, time.Time{})
	require.NoError(t, err)
	return secret.Reveal()
}

func (f mcpFixture) call(t *testing.T, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, mcpPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	return rec
}

// toolResult is the result of one tools/call reply.
type toolResult struct {
	IsError           bool            `json:"isError"`
	Content           []toolText      `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent"`
}

type toolText struct {
	Text string `json:"text"`
}

func (f mcpFixture) callTool(t *testing.T, bearer, tool string, args any) toolResult {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": tool, "arguments": args})
	require.NoError(t, err)
	rec := f.call(t, bearer, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+string(params)+`}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var reply struct {
		Result toolResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &reply), rec.Body.String())
	return reply.Result
}

func TestMCPRefusesACallerWithoutAccess(t *testing.T) {
	tests := []struct {
		name     string
		grantMCP bool
		scopes   []string
		bearer   string
		want     int
		www      string
	}{
		{name: "no bearer", grantMCP: true, want: http.StatusUnauthorized, www: "Bearer " + mcpResourceMetadata},
		{name: "unknown token", grantMCP: true, bearer: "idp_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", want: http.StatusUnauthorized, www: `Bearer error="invalid_token", ` + mcpResourceMetadata},
		{name: "token scope misses /mcp", grantMCP: true, scopes: []string{"https://app.example.test/api/"}, want: http.StatusForbidden},
		{name: "no grant on the mcp resource", scopes: []string{"https://id.example.test/mcp"}, want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newMCPFixture(t, tt.grantMCP)
			bearer := tt.bearer
			if bearer == "" && tt.name != "no bearer" {
				bearer = fixture.issue(t, tt.scopes...)
			}
			rec := fixture.call(t, bearer, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
			assert.Equal(t, tt.want, rec.Code)
			assert.Equal(t, tt.www, rec.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestMCPMintTokenReachesOnlyItsScopes(t *testing.T) {
	fixture := newMCPFixture(t, true)
	bearer := fixture.issue(t, "https://id.example.test/mcp")

	result := fixture.callTool(t, bearer, "mint_token", map[string]any{"scopes": []string{"https://app.example.test/api/v1"}, "name": "smoke"})
	require.False(t, result.IsError, result.Content)
	var minted mintTokenOutput
	require.NoError(t, json.Unmarshal(result.StructuredContent, &minted))
	assert.True(t, strings.HasPrefix(minted.Token, tokens.SecretMarker))
	assert.Equal(t, []string{"https://app.example.test/api/v1"}, minted.Scopes)
	assert.WithinDuration(t, time.Now().Add(mintedTokenLifetime), minted.ExpiresAt, time.Minute)

	stored, err := fixture.issuer.List(t.Context(), fixture.user.ID)
	require.NoError(t, err)
	require.Len(t, stored, 2)
	assert.Contains(t, []string{stored[0].Name.String(), stored[1].Name.String()}, "mcp: smoke")

	check := func(uri string) int {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
		req.Header.Set("Authorization", "Bearer "+minted.Token)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "app.example.test")
		req.Header.Set("X-Forwarded-Uri", uri)
		rec := httptest.NewRecorder()
		fixture.router.ServeHTTP(rec, req)
		return rec.Code
	}
	assert.Equal(t, http.StatusOK, check("/api/v1/me"))
	assert.Equal(t, http.StatusForbidden, check("/api/v2/me"))
	assert.Equal(t, http.StatusForbidden, fixture.call(t, minted.Token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Code)
}

func TestMCPMintTokenRefusesScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   toolRefusal
	}{
		{name: "no scope", scopes: []string{}, want: errMintNoScope},
		{name: "scope with a query", scopes: []string{"https://app.example.test/api/?x=1"}, want: errMintScope},
		{name: "scope on the miniauth host", scopes: []string{"https://id.example.test/mcp"}, want: errMintOwnHost},
		{name: "resource with no grant", scopes: []string{"https://other.example.test/"}, want: errMintNoGrant},
		{name: "scope wider than the resource", scopes: []string{"https://app.example.test/"}, want: errMintNoGrant},
		{name: "host with no resource", scopes: []string{"https://unknown.example.test/"}, want: errMintNoGrant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newMCPFixture(t, true)
			bearer := fixture.issue(t, "https://id.example.test/mcp")
			result := fixture.callTool(t, bearer, "mint_token", map[string]any{"scopes": tt.scopes})
			require.True(t, result.IsError)
			require.NotEmpty(t, result.Content)
			assert.Contains(t, result.Content[0].Text, string(tt.want))
			stored, err := fixture.issuer.List(t.Context(), fixture.user.ID)
			require.NoError(t, err)
			assert.Len(t, stored, 1)
		})
	}
}

func TestMCPListResourcesShowsGrantedPrefixes(t *testing.T) {
	fixture := newMCPFixture(t, true)
	bearer := fixture.issue(t, "https://id.example.test/mcp")
	result := fixture.callTool(t, bearer, "list_resources", map[string]any{})
	require.False(t, result.IsError, result.Content)
	var listed listResourcesOutput
	require.NoError(t, json.Unmarshal(result.StructuredContent, &listed))
	assert.Equal(t, []mcpResource{{Name: "app", URL: "https://app.example.test/api/"}}, listed.Resources)
}
