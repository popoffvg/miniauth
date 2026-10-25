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
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal(err)
	}
	root := repoRoot(t)
	compose := func(args ...string) {
		t.Helper()
		// Background: cleanup runs after the test context is canceled.
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-p", "miniauth-authcheck", "-f", "compose.yaml"}, args...)...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	compose("down", "-v", "--remove-orphans")
	t.Cleanup(func() { compose("down", "-v", "--remove-orphans") })
	compose("up", "-d", "--build", "--wait")

	base := "http://127.0.0.1:8088"
	waitFor(t, base+"/healthz", http.StatusNoContent)

	browser := request(t, http.MethodGet, base+"/app/", "text/html", "")
	if browser.status != http.StatusFound {
		t.Fatalf("browser status = %d, body %s", browser.status, browser.body)
	}
	if !strings.Contains(browser.location, "/login?return=") {
		t.Fatalf("location = %s", browser.location)
	}
	if strings.Contains(browser.body, "X-Auth-User") || strings.Contains(browser.body, "Hostname") {
		t.Fatalf("the test page was served: %s", browser.body)
	}

	apiCall := request(t, http.MethodGet, base+"/app/", "application/json", "")
	if apiCall.status != http.StatusUnauthorized || apiCall.www != "Bearer" {
		t.Fatalf("api status = %d www = %q body %s", apiCall.status, apiCall.www, apiCall.body)
	}

	ctx := t.Context()
	pool, err := postgres.Open(ctx, "postgres://miniauth:miniauth@127.0.0.1:5432/miniauth?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	accounts := users.NewService(postgres.NewUserRepository(pool))
	login, err := users.ParseLogin("ada")
	if err != nil {
		t.Fatal(err)
	}
	password, err := users.NewPassword("test-password-1")
	if err != nil {
		t.Fatal(err)
	}
	account, err := accounts.Create(ctx, login, password)
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := sessions.NewService(postgres.NewSessionRepository(pool)).Start(ctx, account.ID, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	secret := id.CookieValue()
	cookie := sessions.CookieName + "=" + secret

	editors := request(t, http.MethodGet, base+"/editors/", "text/html", cookie)
	if editors.status != http.StatusForbidden {
		t.Fatalf("editors before membership = %d body %s", editors.status, redact(editors.body, secret))
	}
	if strings.Contains(editors.body, "Hostname") {
		t.Fatalf("the editors page was served: %s", redact(editors.body, secret))
	}

	page := request(t, http.MethodGet, base+"/app/", "text/html", cookie)
	if page.status != http.StatusOK || !strings.Contains(page.body, "X-Auth-User: ada") {
		t.Fatalf("app status = %d body %s", page.status, redact(page.body, secret))
	}
	if !strings.Contains(page.body, "X-Auth-Method: password") {
		t.Fatalf("method header missing: %s", redact(page.body, secret))
	}

	name, err := groups.ParseName("editors")
	if err != nil {
		t.Fatal(err)
	}
	if err = postgres.NewGroupRepository(pool).Add(ctx, account.ID, name); err != nil {
		t.Fatal(err)
	}
	allowed := request(t, http.MethodGet, base+"/editors/", "text/html", cookie)
	if allowed.status != http.StatusOK || !strings.Contains(allowed.body, "X-Auth-Groups: editors") {
		t.Fatalf("editors status = %d body %s", allowed.status, redact(allowed.body, secret))
	}
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
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", accept)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	res, err := redirectStop.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return httpResult{
		status:   res.StatusCode,
		location: res.Header.Get("Location"),
		www:      res.Header.Get("WWW-Authenticate"),
		body:     string(body),
	}
}

func waitFor(t *testing.T, target string, want int) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		res, err := http.DefaultClient.Do(req)
		cancel()
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == want {
				return
			}
		}
		last = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s: %v", target, last)
}
