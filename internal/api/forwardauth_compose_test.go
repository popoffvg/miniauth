package api

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestTraefikProtectsThePage(t *testing.T) {
	if os.Getenv("MINIAUTH_COMPOSE") == "" {
		t.Skip("set MINIAUTH_COMPOSE=1 to start the local Traefik stack")
	}
	_, lookErr := exec.LookPath("docker")
	require.NoError(t, lookErr)
	root := repoRoot(t)
	compose := func(args ...string) {
		t.Helper()
		// compose down must finish after the test ends, so it cannot use t.Context.
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-p", "miniauth-authcheck", "-f", "compose.yaml"}, args...)...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "docker compose %s\n%s", strings.Join(args, " "), out)
	}
	compose("down", "-v", "--remove-orphans")
	t.Cleanup(func() { compose("down", "-v", "--remove-orphans") })
	compose("up", "-d", "--build", "--wait")

	base := "http://127.0.0.1:8088"
	waitFor(t, base+"/healthz", http.StatusNoContent)

	browser := request(t, http.MethodGet, base+"/app/", "text/html", "")
	require.Equal(t, http.StatusFound, browser.status, browser.body)
	require.Contains(t, browser.location, "/login?return=")
	require.NotContains(t, browser.body, "X-Auth-User")
	require.NotContains(t, browser.body, "Hostname")

	apiCall := request(t, http.MethodGet, base+"/app/", "application/json", "")
	require.Equal(t, http.StatusUnauthorized, apiCall.status, apiCall.body)
	require.Equal(t, "Bearer", apiCall.www)

	ctx := t.Context()
	pool, err := postgres.Open(ctx, "postgres://miniauth:miniauth@127.0.0.1:5432/miniauth?sslmode=disable")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	accounts := users.NewService(postgres.NewUserRepository(pool))
	login, err := users.ParseLogin("ada")
	require.NoError(t, err)
	password, err := users.NewPassword("test-password-1")
	require.NoError(t, err)
	user, err := accounts.Create(ctx, login, password)
	require.NoError(t, err)
	id, _, err := sessions.NewService(postgres.NewSessionRepository(pool)).Start(ctx, user.ID, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	secret := id.CookieValue()
	cookie := sessions.CookieName + "=" + secret

	grants, err := postgres.NewAccessRepository(pool)
	require.NoError(t, err)
	resources := access.NewService(grants)
	// Traefik forwards the Host header the client sent: 127.0.0.1:8088.
	appResource := createResource(t, resources, "app", "127.0.0.1:8088", "/app")
	editorsResource := createResource(t, resources, "editors", "127.0.0.1:8088", "/editors")
	name, err := groups.ParseName("editors")
	require.NoError(t, err)
	grantResource(t, resources, editorsResource, access.GroupSubject(name))

	noGrant := request(t, http.MethodGet, base+"/app/", "text/html", cookie)
	require.Equal(t, http.StatusForbidden, noGrant.status, redact(noGrant.body, secret))
	require.Contains(t, noGrant.body, "http://127.0.0.1:8088/app/")
	require.NotContains(t, noGrant.body, "Hostname")
	appGrant := grantResource(t, resources, appResource, access.UserSubject(user.ID))

	editors := request(t, http.MethodGet, base+"/editors/", "text/html", cookie)
	require.Equal(t, http.StatusForbidden, editors.status, redact(editors.body, secret))
	require.NotContains(t, editors.body, "Hostname")

	page := request(t, http.MethodGet, base+"/app/", "text/html", cookie)
	require.Equal(t, http.StatusOK, page.status, redact(page.body, secret))
	require.Contains(t, page.body, "X-Auth-User: ada")
	require.Contains(t, page.body, "X-Auth-Method: password")

	memberships, err := postgres.NewGroupRepository(pool)
	require.NoError(t, err)
	require.NoError(t, memberships.Add(ctx, user.ID, name))
	allowed := request(t, http.MethodGet, base+"/editors/", "text/html", cookie)
	require.Equal(t, http.StatusOK, allowed.status, redact(allowed.body, secret))
	require.Contains(t, allowed.body, "X-Auth-Groups: editors")

	require.NoError(t, resources.Revoke(ctx, appGrant))
	revoked := request(t, http.MethodGet, base+"/app/", "application/json", cookie)
	require.Equal(t, http.StatusForbidden, revoked.status, redact(revoked.body, secret))
}

func redact(body, secret string) string {
	if secret == "" {
		return body
	}
	return strings.ReplaceAll(body, secret, "redacted")
}

var redirectStop = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type httpResult struct {
	status   int
	location string
	www      string
	body     string
}

func request(t *testing.T, method, target, accept, cookie string) httpResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, method, target, nil)
	require.NoError(t, err)
	httpRequest.Header.Set("Accept", accept)
	if cookie != "" {
		httpRequest.Header.Set("Cookie", cookie)
	}
	response, err := redirectStop.Do(httpRequest)
	require.NoError(t, err)
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	require.NoError(t, err)
	return httpResult{
		status:   response.StatusCode,
		location: response.Header.Get("Location"),
		www:      response.Header.Get("WWW-Authenticate"),
		body:     string(body),
	}
}

func waitFor(t *testing.T, target string, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return false
		}
		response, err := http.DefaultClient.Do(httpRequest)
		if err != nil {
			return false
		}
		defer func() { _ = response.Body.Close() }()
		return response.StatusCode == want
	}, 60*time.Second, 500*time.Millisecond)
}
