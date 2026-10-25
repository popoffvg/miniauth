package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const fakeSeed uint64 = 20261024

func TestCreateUser(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed)
	fake := gofakeit.New(fakeSeed)
	login := fake.Regex(`[a-z][a-z0-9]{7}`)
	password := fake.Password(true, true, true, true, false, 20)
	const token = "bootstrap-token-for-tests"
	repo := &memRepo{}
	router := mustRouter(t, repo, token)

	valid := `{"login":"` + login + `","password":"` + password + `"}`
	tests := []struct {
		name        string
		token       string
		body        string
		contentType string
		want        int
	}{
		{name: "no token", body: valid, contentType: "application/json", want: http.StatusUnauthorized},
		{name: "wrong token", token: "wrong-token", body: valid, contentType: "application/json", want: http.StatusUnauthorized},
		{name: "text body", token: token, body: valid, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "bad json", token: token, body: "{" + password, contentType: "application/json", want: http.StatusBadRequest},
		{name: "bad login", token: token, body: `{"login":"bad login","password":"x"}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "empty password", token: token, body: `{"login":"` + login + `","password":""}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "long password", token: token, body: `{"login":"` + login + `","password":"` + strings.Repeat("a", users.MaxPasswordBytes+1) + `"}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "large body", token: token, body: strings.Repeat("a", maxCreateUserBody+1), contentType: "application/json", want: http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := post(t, router, tt.token, tt.body, tt.contentType)
			require.Equal(t, tt.want, rec.Code)
			if tt.want == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
			}
			assert.Contains(t, rec.Header().Get("Content-Type"), "application/problem+json")
			assert.NotContains(t, rec.Body.String(), password)
			assert.NotContains(t, rec.Body.String(), token)
			assert.NotContains(t, rec.Body.String(), "bad login")
		})
	}

	t.Run("created", func(t *testing.T) {
		rec := post(t, router, token, valid, "application/json")
		require.Equal(t, http.StatusCreated, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
		var created createdUser
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
		assert.Equal(t, login, created.Login.String())
		assert.NotEqual(t, users.ID{}, created.ID)
		assert.NotContains(t, rec.Body.String(), password)
		assert.NotContains(t, rec.Body.String(), "$schema")

		stored, ok := repo.get(mustLogin(t, login))
		require.True(t, ok)
		assert.Equal(t, users.KindPassword, stored.identity.Kind)
		encoded := stored.identity.Secret.Encoded()
		assert.True(t, strings.HasPrefix(encoded, "$argon2id$"))
		assert.NotContains(t, encoded, password)
		pw, err := users.NewPassword(password)
		require.NoError(t, err)
		matches, err := stored.identity.Secret.Matches(pw)
		require.NoError(t, err)
		assert.True(t, matches)
	})

	t.Run("duplicate login", func(t *testing.T) {
		rec := post(t, router, token, valid, "application/json")
		require.Equal(t, http.StatusConflict, rec.Code)
		assert.NotContains(t, rec.Body.String(), password)
		assert.Equal(t, 1, repo.count())
	})
}

func post(t *testing.T, router http.Handler, token, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func mustRouter(t *testing.T, repo users.Repository, token string) http.Handler {
	t.Helper()
	router, err := NewRouter(users.NewService(repo), sessions.NewService(newMemSessions()), sessions.Domain{}, hashToken(t, token), slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return router
}

func loggedRouter(t *testing.T, repo users.Repository, token string) (http.Handler, *strings.Builder) {
	t.Helper()
	logs := &strings.Builder{}
	router, err := NewRouter(users.NewService(repo), sessions.NewService(newMemSessions()), sessions.Domain{}, hashToken(t, token), slog.New(slog.NewTextHandler(logs, nil)))
	require.NoError(t, err)
	return router, logs
}

func hashToken(t *testing.T, token string) AdminTokenHash {
	t.Helper()
	sum := sha256.Sum256([]byte(token))
	hash, err := ParseAdminTokenHash(hex.EncodeToString(sum[:]))
	require.NoError(t, err)
	return hash
}

func mustLogin(t *testing.T, raw string) users.Login {
	t.Helper()
	login, err := users.ParseLogin(raw)
	require.NoError(t, err)
	return login
}

type storedUser struct {
	account  users.User
	identity users.Identity
}

type memRepo struct {
	mu      sync.Mutex
	byLogin map[users.Login]storedUser
}

func (m *memRepo) Create(_ context.Context, account users.User, identity users.Identity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byLogin == nil {
		m.byLogin = map[users.Login]storedUser{}
	}
	if _, ok := m.byLogin[account.Login]; ok {
		return users.ErrLoginTaken
	}
	m.byLogin[account.Login] = storedUser{account: account, identity: identity}
	return nil
}

func (m *memRepo) get(login users.Login) (storedUser, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored, ok := m.byLogin[login]
	return stored, ok
}

func (m *memRepo) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byLogin)
}

type failRepo struct{}

func (failRepo) Create(context.Context, users.User, users.Identity) error {
	return errors.New("database is down")
}
