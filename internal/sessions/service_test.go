package sessions

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestExtendWritesAtMostOncePerHour(t *testing.T) {
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	current := start
	repo := newMemRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return current }

	id, started, err := svc.Start(t.Context(), users.NewID(), loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	if repo.extends != 0 {
		t.Fatalf("start extend writes = %d", repo.extends)
	}
	stored, ok := repo.byHash(id.Hash())
	if !ok {
		t.Fatal("session is not stored under its hash")
	}
	raw := id.Bytes()
	if bytes.Equal(stored[:], raw[:]) {
		t.Fatal("repository stored the session id")
	}

	bursts := []struct {
		at   time.Duration
		want int
	}{
		{at: 0, want: 0},
		{at: 30 * time.Minute, want: 0},
		{at: time.Hour - time.Nanosecond, want: 0},
		{at: time.Hour, want: 1},
		{at: time.Hour + time.Minute, want: 1},
		{at: 2 * time.Hour, want: 2},
		{at: 3*time.Hour - time.Microsecond, want: 2},
		{at: 3 * time.Hour, want: 3},
	}
	previous := 0
	for _, burst := range bursts {
		current = start.Add(burst.at)
		extended := 0
		var opened Session
		for range 4 {
			got, wrote, err := svc.Open(t.Context(), id)
			if err != nil {
				t.Fatalf("open at %s: %v", burst.at, err)
			}
			if wrote {
				extended++
			}
			opened = got
		}
		if repo.extends != burst.want {
			t.Fatalf("at %s extend writes = %d, want %d", burst.at, repo.extends, burst.want)
		}
		if burst.want == previous && extended != 0 {
			t.Fatalf("at %s extended %d times inside the hour", burst.at, extended)
		}
		if burst.want != previous && extended != 1 {
			t.Fatalf("at %s extended %d times, want 1", burst.at, extended)
		}
		previous = burst.want
		if !opened.AuthAt.Equal(started.AuthAt) {
			t.Fatalf("auth_at = %s, want %s", opened.AuthAt, started.AuthAt)
		}
		wantExpiry := start.Add(time.Duration(burst.want) * time.Hour).Add(Lifetime)
		if !opened.ExpiresAt.Equal(wantExpiry) {
			t.Fatalf("at %s expires_at = %s, want %s", burst.at, opened.ExpiresAt, wantExpiry)
		}
	}
}

func TestOpenDeletesAnExpiredSession(t *testing.T) {
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	current := start
	repo := newMemRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return current }
	id, _, err := svc.Start(t.Context(), users.NewID(), loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	current = start.Add(Lifetime)
	if _, _, err := svc.Open(t.Context(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("open expired = %v, want ErrNotFound", err)
	}
	if repo.extends != 0 {
		t.Fatalf("expired open extend writes = %d", repo.extends)
	}
	if _, ok := repo.byHash(id.Hash()); ok {
		t.Fatal("expired session is still stored")
	}
}

func TestLogoutDeletesOneSession(t *testing.T) {
	repo := newMemRepo()
	svc := NewService(repo)
	user := users.NewID()
	first, _, err := svc.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := svc.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.Logout(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	if err = svc.Logout(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.Open(t.Context(), first)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("open after logout = %v", err)
	}
	_, _, err = svc.Open(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	err = svc.LogoutEverywhere(t.Context(), unknown)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("logout everywhere unknown = %v", err)
	}
	_, _, err = svc.Open(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
}

func TestLogoutEverywhereDeletesOnlyThatUser(t *testing.T) {
	start := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	current := start
	repo := newMemRepo()
	svc := NewService(repo)
	svc.now = func() time.Time { return current }
	user := users.NewID()
	other := users.NewID()
	keep, _, err := svc.Start(t.Context(), other, loginflow.Factors(loginflow.FactorGoogle))
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := svc.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := svc.Start(t.Context(), user, loginflow.Factors(loginflow.FactorTOTP))
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.LogoutEverywhere(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.Open(t.Context(), first)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("first = %v", err)
	}
	_, _, err = svc.Open(t.Context(), second)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("second = %v", err)
	}
	_, _, err = svc.Open(t.Context(), keep)
	if err != nil {
		t.Fatal(err)
	}

	expired, _, err := svc.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	current = start.Add(Lifetime + time.Second)
	fresh, _, err := svc.Start(t.Context(), user, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	err = svc.LogoutEverywhere(t.Context(), expired)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired logout everywhere = %v", err)
	}
	_, _, err = svc.Open(t.Context(), fresh)
	if err != nil {
		t.Fatal(err)
	}
}

func TestStartRejectsAnEmptyUser(t *testing.T) {
	svc := NewService(newMemRepo())
	if _, _, err := svc.Start(t.Context(), users.ID{}, loginflow.Factors(loginflow.FactorPassword)); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("start = %v", err)
	}
}

type memRepo struct {
	mu      sync.Mutex
	rows    map[Hash]Session
	extends int
}

func newMemRepo() *memRepo {
	return &memRepo{rows: map[Hash]Session{}}
}

func (m *memRepo) Create(_ context.Context, session Session, hash Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[hash] = session
	return nil
}

func (m *memRepo) Find(_ context.Context, hash Hash) (Session, Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.rows[hash]
	if !ok {
		return Session{}, Hash{}, ErrNotFound
	}
	return session, hash, nil
}

func (m *memRepo) Extend(_ context.Context, hash Hash, expiresAt, extendBefore time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.extends++
	session, ok := m.rows[hash]
	if !ok || session.ExpiresAt.After(extendBefore) {
		return false, nil
	}
	session.ExpiresAt = expiresAt
	m.rows[hash] = session
	return true, nil
}

func (m *memRepo) Delete(_ context.Context, hash Hash) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, hash)
	return nil
}

func (m *memRepo) DeleteUser(_ context.Context, userID users.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, session := range m.rows {
		if session.UserID == userID {
			delete(m.rows, hash)
		}
	}
	return nil
}

func (m *memRepo) byHash(hash Hash) (Hash, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.rows[hash]
	return hash, ok
}
