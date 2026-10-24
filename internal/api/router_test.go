package api

import (
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/user"
)

func TestHealthz(t *testing.T) {
	router := mustRouter(t, nil, "bootstrap-token-for-tests")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.NotEmpty(t, rec.Header().Get("X-Request-ID"))
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
	assert.Contains(t, body, "/api/v1/users")
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
	assert.Equal(t, strconv.Itoa(user.MaxLoginLength), login.Tag.Get("maxLength"))
	assert.Equal(t, strconv.Itoa(user.MaxPasswordBytes), password.Tag.Get("maxLength"))
}

func TestRequestLogOmitsSecrets(t *testing.T) {
	const token = "bootstrap-token-for-tests"
	const password = "correct horse battery staple"
	router, logs := loggedRouter(t, &memRepo{}, token)
	body := `{"login":"ada","password":"` + password + `"}`
	query := url.Values{}
	query.Set("access_token", token)
	query.Set("password", password)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users?"+query.Encode(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.NotEqual(t, token, rec.Header().Get("X-Request-ID"))
	text := logs.String()
	assert.Contains(t, text, "http request")
	assert.Contains(t, text, "request_id")
	assert.NotContains(t, text, token)
	assert.NotContains(t, text, password)
	assert.NotContains(t, text, "access_token")
	assert.NotContains(t, rec.Body.String(), token)
	assert.NotContains(t, rec.Body.String(), password)
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

func TestAuthFailsClosed(t *testing.T) {
	svc := &service{}
	for _, rt := range svc.routes() {
		if rt.public {
			continue
		}
		assert.NotEmpty(t, rt.method)
		assert.NotEmpty(t, rt.path)
		assert.False(t, rt.public)
	}
	var sawPublic bool
	for _, rt := range svc.routes() {
		if rt.path == "/healthz" {
			assert.True(t, rt.public)
			sawPublic = true
		}
	}
	assert.True(t, sawPublic)
}
