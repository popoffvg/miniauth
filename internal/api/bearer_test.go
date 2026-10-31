package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestForwardAuthAccessToken(t *testing.T) {
	const invalid = `Bearer error="invalid_token"`
	tests := []struct {
		name          string
		scopes        []string
		revoked       bool
		expired       bool
		disabled      bool
		ownerDeleted  bool
		groups        []string
		query         string
		authorization string
		host          string
		uri           string
		want          int
		www           string
	}{
		{name: "valid token with no scope reaches every url", uri: "/any/path", want: http.StatusOK},
		{name: "valid token under its scope", scopes: []string{"https://app.example.test/mcp"}, uri: "/mcp", want: http.StatusOK},
		{name: "scope covers a deeper path", scopes: []string{"https://app.example.test/mcp"}, uri: "/mcp/tools?x=1", want: http.StatusOK},
		{name: "scope with a trailing slash covers its own path", scopes: []string{"https://app.example.test/mcp/"}, uri: "/mcp", want: http.StatusOK},
		{name: "second scope covers the url", scopes: []string{"https://app.example.test/api", "https://app.example.test/mcp"}, uri: "/mcp/x", want: http.StatusOK},
		{name: "host scope covers every path", scopes: []string{"https://app.example.test"}, uri: "/a/b", want: http.StatusOK},
		{name: "scope ends on a segment border", scopes: []string{"https://app.example.test/mcp"}, uri: "/mcpx", want: http.StatusForbidden},
		{name: "url under no scope", scopes: []string{"https://app.example.test/mcp"}, uri: "/admin", want: http.StatusForbidden},
		{name: "other host is under no scope", scopes: []string{"https://app.example.test/mcp"}, host: "other.example.test", uri: "/mcp", want: http.StatusForbidden},
		{name: "dot segment escapes no scope", scopes: []string{"https://app.example.test/mcp"}, uri: "/mcp/../admin", want: http.StatusForbidden},
		{name: "encoded slash escapes no scope", scopes: []string{"https://app.example.test/mcp"}, uri: "/mcp%2F..%2Fadmin", want: http.StatusForbidden},
		{name: "revoked token", revoked: true, want: http.StatusUnauthorized, www: invalid},
		{name: "expired token", expired: true, want: http.StatusUnauthorized, www: invalid},
		{name: "disabled user", disabled: true, want: http.StatusUnauthorized, www: invalid},
		{name: "deleted user", ownerDeleted: true, want: http.StatusUnauthorized, www: invalid},
		{name: "unknown token", authorization: "Bearer idp_" + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", want: http.StatusUnauthorized, www: invalid},
		{name: "malformed token", authorization: "Bearer idp_short", want: http.StatusUnauthorized, www: invalid},
		{name: "user in the group", groups: []string{"editors"}, query: "group=editors", want: http.StatusOK},
		{name: "user outside the group", query: "group=editors", want: http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accounts := &memRepo{}
			members := newMemGroups()
			store := newMemTokens()
			access := tokens.NewService(store)
			user := users.User{ID: users.NewID(), Login: mustLogin(t, "ada@example.test"), CreatedAt: time.Now().UTC()}
			if tt.disabled {
				user.DisabledAt = time.Now().UTC()
			}
			if !tt.ownerDeleted {
				accounts.put(user)
			}
			for _, raw := range tt.groups {
				name, err := groups.ParseName(raw)
				require.NoError(t, err)
				require.NoError(t, members.Add(t.Context(), user.ID, name))
			}
			scopes, err := tokens.ParseScopes(tt.scopes)
			require.NoError(t, err)
			name, err := tokens.ParseName("ci")
			require.NoError(t, err)
			secret, issued, err := access.Issue(t.Context(), user.ID, name, scopes, time.Time{})
			require.NoError(t, err)
			if tt.revoked {
				require.NoError(t, access.Revoke(t.Context(), user.ID, issued.ID))
			}
			if tt.expired {
				store.expire(issued.ID)
			}
			router, err := NewRouter(users.NewService(accounts), sessions.NewService(newMemSessions()), members, sessions.Domain{}, PublicURL{}, hashToken(t, "bootstrap-token-for-tests"), &readyState{ok: true}, slog.New(slog.DiscardHandler), WithAccessTokens(access))
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
			req.URL.RawQuery = tt.query
			authorization := tt.authorization
			if authorization == "" {
				authorization = "Bearer " + secret.Reveal()
			}
			req.Header.Set("Authorization", authorization)
			req.Header.Set("Accept", "text/html")
			host := tt.host
			if host == "" {
				host = "app.example.test"
			}
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", host)
			req.Header.Set("X-Forwarded-Uri", tt.uri)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, tt.want, rec.Code)
			assert.Equal(t, tt.www, rec.Header().Get("WWW-Authenticate"))
			assert.Empty(t, rec.Header().Get("Location"))
			assert.NotContains(t, rec.Body.String(), secret.Reveal())
			if tt.want == http.StatusOK {
				assert.Equal(t, "ada@example.test", rec.Header().Get(headerAuthUser))
				assert.Equal(t, "ada@example.test", rec.Header().Get(headerAuthEmail))
				assert.Equal(t, "token", rec.Header().Get(headerAuthMethod))
				assert.Equal(t, joinGroupNames(t, tt.groups), rec.Header().Get(headerAuthGroups))
			} else {
				assert.Empty(t, rec.Header().Get(headerAuthUser))
				assert.Empty(t, rec.Header().Get(headerAuthMethod))
			}
		})
	}
}

func TestForwardAuthAccessTokenWithoutTokenService(t *testing.T) {
	router := forwardRouter(t, &memRepo{}, sessions.NewService(newMemSessions()), newMemGroups(), sessions.Domain{}, PublicURL{})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
	req.Header.Set("Authorization", "Bearer idp_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, rec.Header().Get("WWW-Authenticate"))
}

func TestForwardAuthAccessTokenStoreFailure(t *testing.T) {
	access := tokens.NewService(failTokens{})
	router, err := NewRouter(users.NewService(&memRepo{}), sessions.NewService(newMemSessions()), nil, sessions.Domain{}, PublicURL{}, hashToken(t, "bootstrap-token-for-tests"), &readyState{ok: true}, slog.New(slog.DiscardHandler), WithAccessTokens(access))
	require.NoError(t, err)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/check", nil)
	req.Header.Set("Authorization", "Bearer idp_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "The check failed.")
	assert.NotContains(t, rec.Body.String(), "tokens are down")
}

func joinGroupNames(t *testing.T, raw []string) string {
	t.Helper()
	names := make([]groups.Name, 0, len(raw))
	for _, value := range raw {
		name, err := groups.ParseName(value)
		require.NoError(t, err)
		names = append(names, name)
	}
	return joinGroups(names)
}

type memTokens struct {
	mu     sync.Mutex
	byHash map[tokens.Hash]tokens.Token
}

func newMemTokens() *memTokens {
	return &memTokens{byHash: map[tokens.Hash]tokens.Token{}}
}

func (m *memTokens) Create(_ context.Context, token tokens.Token, hash tokens.Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byHash[hash]; ok {
		return tokens.ErrDuplicate
	}
	m.byHash[hash] = token
	return nil
}

func (m *memTokens) Find(_ context.Context, hash tokens.Hash) (tokens.Token, tokens.Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.byHash[hash]
	if !ok {
		return tokens.Token{}, tokens.Hash{}, tokens.ErrInvalid
	}
	return token, hash, nil
}

func (m *memTokens) List(_ context.Context, userID users.ID) ([]tokens.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []tokens.Token
	for _, token := range m.byHash {
		if token.UserID == userID {
			out = append(out, token)
		}
	}
	return out, nil
}

func (m *memTokens) Revoke(_ context.Context, userID users.ID, id tokens.ID, at time.Time) error {
	return m.update(id, func(token *tokens.Token) bool {
		if token.UserID != userID {
			return false
		}
		if token.RevokedAt.IsZero() {
			token.RevokedAt = at
		}
		return true
	})
}

func (m *memTokens) Touch(_ context.Context, id tokens.ID, at, touchBefore time.Time) error {
	err := m.update(id, func(token *tokens.Token) bool {
		if token.LastUsedAt.IsZero() || !token.LastUsedAt.After(touchBefore) {
			token.LastUsedAt = at
		}
		return true
	})
	if errors.Is(err, tokens.ErrNotFound) {
		return nil
	}
	return err
}

func (m *memTokens) expire(id tokens.ID) {
	_ = m.update(id, func(token *tokens.Token) bool {
		token.ExpiresAt = time.Now().Add(-time.Minute)
		return true
	})
}

func (m *memTokens) update(id tokens.ID, change func(*tokens.Token) bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, token := range m.byHash {
		if token.ID != id {
			continue
		}
		if !change(&token) {
			return tokens.ErrNotFound
		}
		m.byHash[hash] = token
		return nil
	}
	return tokens.ErrNotFound
}

type failTokens struct{}

func (failTokens) Create(context.Context, tokens.Token, tokens.Hash) error {
	return errors.New("tokens are down")
}

func (failTokens) Find(context.Context, tokens.Hash) (tokens.Token, tokens.Hash, error) {
	return tokens.Token{}, tokens.Hash{}, errors.New("tokens are down")
}

func (failTokens) List(context.Context, users.ID) ([]tokens.Token, error) {
	return nil, errors.New("tokens are down")
}

func (failTokens) Revoke(context.Context, users.ID, tokens.ID, time.Time) error {
	return errors.New("tokens are down")
}

func (failTokens) Touch(context.Context, tokens.ID, time.Time, time.Time) error {
	return errors.New("tokens are down")
}

var _ tokens.Repository = (*memTokens)(nil)
