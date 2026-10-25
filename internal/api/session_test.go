package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestLogoutDeletesOnlyThatSession(t *testing.T) {
	repo := newMemSessions()
	browser := sessions.NewService(repo)
	domain := mustDomain(t, "example.test")
	user := users.NewID()
	id, _, err := browser.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	other, _, err := browser.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	router := sessionRouter(t, browser, domain)

	rec := postCookie(t, router, "/logout", id)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.NotContains(t, rec.Header().Get("Set-Cookie"), id.CookieValue())
	cleared := mustParseSetCookie(t, rec)
	assert.Equal(t, sessions.CookieName, cleared.Name)
	assert.Empty(t, cleared.Value)
	assert.Negative(t, cleared.MaxAge)
	assert.Equal(t, "example.test", cleared.Domain)
	assert.True(t, cleared.HttpOnly)
	assert.True(t, cleared.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cleared.SameSite)

	_, _, err = browser.Open(t.Context(), id)
	require.ErrorIs(t, err, sessions.ErrNotFound)
	_, _, err = browser.Open(t.Context(), other)
	require.NoError(t, err)
}

func TestLogoutWithoutACookieStillClearsIt(t *testing.T) {
	router := sessionRouter(t, sessions.NewService(newMemSessions()), mustDomain(t, "example.test"))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	cleared := mustParseSetCookie(t, rec)
	assert.Equal(t, "example.test", cleared.Domain)
	assert.Negative(t, cleared.MaxAge)
}

func TestLogoutEverywhere(t *testing.T) {
	repo := newMemSessions()
	browser := sessions.NewService(repo)
	domain := mustDomain(t, "example.test")
	user := users.NewID()
	factors := loginflow.Factors(loginflow.FactorPassword | loginflow.FactorTOTP)
	first, _, err := browser.Start(t.Context(), user, factors)
	require.NoError(t, err)
	second, _, err := browser.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	require.NoError(t, err)
	kept, _, err := browser.Start(t.Context(), users.NewID(), loginflow.Factors(loginflow.FactorGoogle))
	require.NoError(t, err)
	router := sessionRouter(t, browser, domain)

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logout/everywhere", nil))
	require.Equal(t, http.StatusUnauthorized, missing.Code)
	assert.Contains(t, missing.Body.String(), "The session is not valid.")
	assert.NotContains(t, missing.Body.String(), "bearer token")
	assert.Equal(t, "Bearer", missing.Header().Get("WWW-Authenticate"))

	rec := postCookie(t, router, "/logout/everywhere", first)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.NotContains(t, rec.Header().Get("Set-Cookie"), first.CookieValue())
	_, _, err = browser.Open(t.Context(), first)
	require.ErrorIs(t, err, sessions.ErrNotFound)
	_, _, err = browser.Open(t.Context(), second)
	require.ErrorIs(t, err, sessions.ErrNotFound)
	_, _, err = browser.Open(t.Context(), kept)
	require.NoError(t, err)
}

func TestLogoutDoesNotNeedTheAdminToken(t *testing.T) {
	router := sessionRouter(t, sessions.NewService(newMemSessions()), sessions.Domain{})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.NotContains(t, rec.Body.String(), "bearer token")
}

func sessionRouter(t *testing.T, browser *sessions.Service, domain sessions.Domain) http.Handler {
	t.Helper()
	router, err := NewRouter(users.NewService(&memRepo{}), browser, nil, domain, PublicURL{}, hashToken(t, "bootstrap-token-for-tests"), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return router
}

func postCookie(t *testing.T, router http.Handler, path string, id sessions.ID) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, nil)
	req.AddCookie(&http.Cookie{Name: sessions.CookieName, Value: id.CookieValue()})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func mustDomain(t *testing.T, raw string) sessions.Domain {
	t.Helper()
	domain, err := sessions.ParseDomain(raw)
	require.NoError(t, err)
	return domain
}

func mustParseSetCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookie, err := http.ParseSetCookie(rec.Header().Get("Set-Cookie"))
	require.NoError(t, err)
	return cookie
}

func newMemSessions() *memSessions {
	return &memSessions{rows: map[sessions.Hash]sessions.Session{}}
}

type memSessions struct {
	mu   sync.Mutex
	rows map[sessions.Hash]sessions.Session
}

func (m *memSessions) Create(_ context.Context, session sessions.Session, hash sessions.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[hash] = session
	return nil
}

func (m *memSessions) Find(_ context.Context, hash sessions.Hash) (sessions.Session, sessions.Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.rows[hash]
	if !ok {
		return sessions.Session{}, sessions.Hash{}, sessions.ErrNotFound
	}
	return session, hash, nil
}

func (m *memSessions) Extend(_ context.Context, hash sessions.Hash, expiresAt, extendBefore time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.rows[hash]
	if !ok || session.ExpiresAt.After(extendBefore) {
		return false, nil
	}
	session.ExpiresAt = expiresAt
	m.rows[hash] = session
	return true, nil
}

func (m *memSessions) Delete(_ context.Context, hash sessions.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, hash)
	return nil
}

func (m *memSessions) DeleteUser(_ context.Context, userID users.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, session := range m.rows {
		if session.UserID == userID {
			delete(m.rows, hash)
		}
	}
	return nil
}

var _ sessions.Repository = (*memSessions)(nil)
