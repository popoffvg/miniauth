package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestHealthz(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.NotEmpty(t, rec.Header().Get("X-Request-ID"))
}

func TestReadyz(t *testing.T) {
	ready := &readyState{ok: true}
	router := mustRouterReady(t, nil, "bootstrap-token-for-tests", ready)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	ready.ok = false
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Empty(t, rec.Body.String())

	closed := mustRouterReady(t, nil, "bootstrap-token-for-tests", nil)
	rec = httptest.NewRecorder()
	closed.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestReadyzRejectsPost(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/readyz", nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestHealthzRejectsPost(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/healthz", nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOpenAPIIsGeneratedFromTheRoutes(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/openapi.yaml", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "yaml")
	body := rec.Body.String()
	assert.Contains(t, body, "/healthz")
	assert.Contains(t, body, "/readyz")
	assert.Contains(t, body, "/api/v1/users")
	assert.Contains(t, body, "/logout")
	assert.Contains(t, body, "/logout/everywhere")
	assert.Contains(t, body, "bearerAuth")
	assert.Contains(t, body, "maxLength: 64")
	assert.Contains(t, body, "maxLength: 1024")

	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	golden := filepath.Join(filepath.Dir(file), "..", "..", "api", "openapi.yaml")
	if os.Getenv("UPDATE_OPENAPI") == "1" {
		require.NoError(t, os.WriteFile(golden, rec.Body.Bytes(), 0o644))
	}
	want, err := os.ReadFile(golden)
	require.NoError(t, err)
	assert.Equal(t, string(want), body)
}

func TestRequestTagsUseTheDomainLimits(t *testing.T) {
	typ := reflect.TypeOf(createUserRequest{})
	login, ok := typ.FieldByName("Login")
	require.True(t, ok)
	password, ok := typ.FieldByName("Password")
	require.True(t, ok)
	assert.Equal(t, strconv.Itoa(users.MaxLoginLength), login.Tag.Get("maxLength"))
	assert.Equal(t, strconv.Itoa(users.MaxPasswordBytes), password.Tag.Get("maxLength"))
}

func TestRequestLogOmitsSecrets(t *testing.T) {
	const token = "bootstrap-token-for-tests"
	const password = "correct horse battery staple"
	spans := recordSpans(t)
	router, logs := loggedRouter(t, &memRepo{}, token)
	body := `{"login":"ada","password":"` + password + `"}`
	query := url.Values{}
	query.Set("access_token", token)
	query.Set("password", password)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users?"+query.Encode(), strings.NewReader(body))
	const sessionCookie = "cookie-value-must-stay-out-of-the-log"
	req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: sessionCookie})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", sessionCookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.NotEqual(t, token, rec.Header().Get("X-Request-ID"))
	assert.NotEqual(t, sessionCookie, rec.Header().Get("X-Request-ID"))
	text := logs.String()
	assert.Contains(t, text, "http request")
	assert.Contains(t, text, "request_id")
	assert.NotContains(t, text, token)
	assert.NotContains(t, text, password)
	assert.NotContains(t, text, sessionCookie)
	assert.NotContains(t, text, "access_token")
	assert.NotContains(t, rec.Body.String(), token)
	assert.NotContains(t, rec.Body.String(), password)
	recorded := spanText(spans.Ended())
	assert.Contains(t, recorded, "POST /api/v1/users")
	assert.Contains(t, recorded, "http.response.status_code=401")
	assert.NotContains(t, recorded, token)
	assert.NotContains(t, recorded, password)
	assert.NotContains(t, recorded, sessionCookie)
	assert.NotContains(t, recorded, "access_token")
}

func TestStoreFailureLogHasNoSecret(t *testing.T) {
	const token = "bootstrap-token-for-tests"
	const password = "correct horse battery staple"
	router, logs := loggedRouter(t, failRepo{}, token)
	body := `{"login":"ada","password":"` + password + `"}`
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), password)
	assert.NotContains(t, rec.Body.String(), "database is down")
	assert.Contains(t, logs.String(), "database is down")
	assert.Contains(t, logs.String(), "request_id")
	assert.NotContains(t, logs.String(), password)
	assert.NotContains(t, logs.String(), token)
}

func recordSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	previous := otel.GetTracerProvider()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	otel.SetTracerProvider(provider)
	t.Cleanup(func() {
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})
	return recorder
}

func spanText(spans []sdktrace.ReadOnlySpan) string {
	var b strings.Builder
	for _, span := range spans {
		b.WriteString(span.Name())
		b.WriteByte('\n')
		for _, attr := range span.Attributes() {
			b.WriteString(string(attr.Key))
			b.WriteByte('=')
			b.WriteString(attr.Value.String())
			b.WriteByte('\n')
		}
		for _, event := range span.Events() {
			b.WriteString(event.Name)
			b.WriteByte('\n')
			for _, attr := range event.Attributes {
				b.WriteString(string(attr.Key))
				b.WriteByte('=')
				b.WriteString(attr.Value.String())
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

func TestAuthFailsClosed(t *testing.T) {
	public := map[string]bool{
		"/healthz":           true,
		"/readyz":            true,
		"/openapi.yaml":      true,
		"/logout":            true,
		"/logout/everywhere": true,
	}
	svc := &service{}
	seen := map[string]bool{}
	for _, rt := range svc.routes() {
		seen[rt.path] = true
		assert.NotEmpty(t, rt.method)
		assert.NotEmpty(t, rt.path)
		if public[rt.path] {
			assert.True(t, rt.public, rt.path)
			continue
		}
		assert.False(t, rt.public, rt.path)
	}
	for path := range public {
		assert.True(t, seen[path], path)
	}
}
