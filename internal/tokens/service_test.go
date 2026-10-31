package tokens

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/users"
)

func TestAuthenticate(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name    string
		expires time.Duration
		revoke  bool
		elapsed time.Duration
		wantErr error
	}{
		{name: "valid token", elapsed: time.Hour},
		{name: "valid before expiry", expires: time.Hour, elapsed: time.Hour - time.Second},
		{name: "expired at the expiry", expires: time.Hour, elapsed: time.Hour, wantErr: ErrInvalid},
		{name: "revoked", revoke: true, wantErr: ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, store, clock := newTestService(start)
			var expiresAt time.Time
			if tt.expires != 0 {
				expiresAt = start.Add(tt.expires)
			}
			secret, issued, err := svc.Issue(t.Context(), users.NewID(), mustName(t), nil, expiresAt)
			require.NoError(t, err)
			if tt.revoke {
				require.NoError(t, svc.Revoke(t.Context(), issued.UserID, issued.ID))
			}
			clock.set(start.Add(tt.elapsed))
			got, err := svc.Authenticate(t.Context(), secret)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Zero(t, store.touches)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, issued.ID, got.ID)
		})
	}
}

func TestLastUsedMovesOncePerMinute(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc, store, clock := newTestService(start)
	secret, _, err := svc.Issue(t.Context(), users.NewID(), mustName(t), nil, time.Time{})
	require.NoError(t, err)

	got, err := svc.Authenticate(t.Context(), secret)
	require.NoError(t, err)
	assert.Equal(t, start, got.LastUsedAt)
	assert.Equal(t, 1, store.touches)

	clock.set(start.Add(UseEvery - time.Second))
	got, err = svc.Authenticate(t.Context(), secret)
	require.NoError(t, err)
	assert.Equal(t, start, got.LastUsedAt)
	assert.Equal(t, 1, store.touches)

	clock.set(start.Add(UseEvery))
	got, err = svc.Authenticate(t.Context(), secret)
	require.NoError(t, err)
	assert.Equal(t, start.Add(UseEvery), got.LastUsedAt)
	assert.Equal(t, 2, store.touches)
}

func TestIssueRefusesBadInput(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc, _, _ := newTestService(start)
	_, _, err := svc.Issue(t.Context(), users.ID{}, mustName(t), nil, time.Time{})
	require.ErrorIs(t, err, ErrUnknownUser)
	_, _, err = svc.Issue(t.Context(), users.NewID(), Name{}, nil, time.Time{})
	require.ErrorIs(t, err, ErrName)
	_, _, err = svc.Issue(t.Context(), users.NewID(), mustName(t), Scopes{{}}, time.Time{})
	require.ErrorIs(t, err, ErrScope)
	_, _, err = svc.Issue(t.Context(), users.NewID(), mustName(t), nil, start)
	require.ErrorIs(t, err, ErrExpiry)
}

func TestImport(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc, _, _ := newTestService(start)
	owner := users.NewID()
	secret, err := ParseSecret("idp_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
	require.NoError(t, err)
	imported, err := svc.Import(t.Context(), owner, mustName(t), nil, secret)
	require.NoError(t, err)
	assert.Equal(t, "idp_0123", imported.Prefix.String())
	assert.True(t, imported.ExpiresAt.IsZero())

	got, err := svc.Authenticate(t.Context(), secret)
	require.NoError(t, err)
	assert.Equal(t, imported.ID, got.ID)

	_, err = svc.Import(t.Context(), owner, mustName(t), nil, secret)
	require.ErrorIs(t, err, ErrDuplicate)
	_, err = svc.Import(t.Context(), owner, mustName(t), nil, Secret{})
	require.ErrorIs(t, err, ErrInvalid)
}

func TestListAndRevokeStayWithTheOwner(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc, _, _ := newTestService(start)
	ada, bea := users.NewID(), users.NewID()
	_, issued, err := svc.Issue(t.Context(), ada, mustName(t), nil, time.Time{})
	require.NoError(t, err)

	list, err := svc.List(t.Context(), ada)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, issued.ID, list[0].ID)
	list, err = svc.List(t.Context(), bea)
	require.NoError(t, err)
	assert.Empty(t, list)

	require.ErrorIs(t, svc.Revoke(t.Context(), bea, issued.ID), ErrNotFound)
	require.NoError(t, svc.Revoke(t.Context(), ada, issued.ID))
	require.NoError(t, svc.Revoke(t.Context(), ada, issued.ID))
}

func mustName(t *testing.T) Name {
	t.Helper()
	name, err := ParseName("ci")
	require.NoError(t, err)
	return name
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *testClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func newTestService(start time.Time) (*Service, *memStore, *testClock) {
	clock := &testClock{now: start}
	store := &memStore{byHash: map[Hash]Token{}}
	return &Service{repo: store, now: clock.read}, store, clock
}

type memStore struct {
	mu      sync.Mutex
	byHash  map[Hash]Token
	touches int
}

func (m *memStore) Create(_ context.Context, token Token, hash Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byHash[hash]; ok {
		return ErrDuplicate
	}
	m.byHash[hash] = token
	return nil
}

func (m *memStore) Find(_ context.Context, hash Hash) (Token, Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.byHash[hash]
	if !ok {
		return Token{}, Hash{}, ErrInvalid
	}
	return token, hash, nil
}

func (m *memStore) List(_ context.Context, userID users.ID) ([]Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Token
	for _, token := range m.byHash {
		if token.UserID == userID {
			out = append(out, token)
		}
	}
	return out, nil
}

func (m *memStore) Revoke(_ context.Context, userID users.ID, id ID, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, token := range m.byHash {
		if token.ID == id && token.UserID == userID {
			if token.RevokedAt.IsZero() {
				token.RevokedAt = at
			}
			m.byHash[hash] = token
			return nil
		}
	}
	return ErrNotFound
}

func (m *memStore) Touch(_ context.Context, id ID, at, touchBefore time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touches++
	for hash, token := range m.byHash {
		if token.ID == id && (token.LastUsedAt.IsZero() || !token.LastUsedAt.After(touchBefore)) {
			token.LastUsedAt = at
			m.byHash[hash] = token
		}
	}
	return nil
}
