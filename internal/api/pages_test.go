package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestRenderPageSetsHeaders(t *testing.T) {
	login, err := users.ParseLogin("ada")
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	renderPage(rec, req, http.StatusOK, pageSignedIn, pageView{Login: login})
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "You are signed in as ada.")
	assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, pageCSP, rec.Header().Get("Content-Security-Policy"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
}

func TestRenderStepsShowsTheOneOpenForm(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil)
	(&service{}).renderSteps(rec, req, http.StatusOK, 0, msgWrongCredentials)
	assert.Contains(t, rec.Body.String(), `name="password"`)
	assert.Contains(t, rec.Body.String(), string(msgWrongCredentials))
	assert.NotContains(t, rec.Body.String(), googleLoginPath, "Google is not offered without the step")
	assert.NotContains(t, rec.Body.String(), "telegram.org", "Telegram is not offered without the step")
	assert.Equal(t, pageCSP, rec.Header().Get("Content-Security-Policy"))
}

func TestRenderStepsListsTheOpenSteps(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil)
	(&service{}).renderSteps(rec, req, http.StatusOK, loginflow.Factors(loginflow.FactorPassword), "")
	assert.Contains(t, rec.Body.String(), "Choose a sign-in method")
	assert.NotContains(t, rec.Body.String(), `name="password"`)
}

func TestFlowCookieRefusesAMalformedValue(t *testing.T) {
	id, err := loginflow.NewFlowID()
	require.NoError(t, err)
	for _, value := range []string{"", "no-dot", id.String() + ".", id.String() + ".!!", "not-a-uuid.AAAA"} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
		req.AddCookie(&http.Cookie{Name: flowCookieName, Value: value})
		_, _, parseErr := flowFromRequest(req)
		assert.ErrorIs(t, parseErr, loginflow.ErrFlowNotFound, value)
	}

	secret, err := loginflow.NewFlowSecret()
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	setFlowCookie(rec, id, secret, time.Now())
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
	gotID, gotSecret, err := flowFromRequest(req)
	require.NoError(t, err)
	assert.Equal(t, id, gotID)
	assert.Equal(t, secret.Bytes(), gotSecret.Bytes())
}
