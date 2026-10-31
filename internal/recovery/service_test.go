package recovery

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/users"
)

type memStore struct {
	mu       sync.Mutex
	accounts map[users.Login]users.User
	resets   map[TokenHash]Reset
}

func (m *memStore) FindAccount(_ context.Context, login users.Login) (users.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	account, ok := m.accounts[login]
	if !ok {
		return users.User{}, users.ErrNotFound
	}
	return account, nil
}

func (m *memStore) Create(_ context.Context, reset Reset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resets[reset.Hash] = reset
	return nil
}

func (m *memStore) FindOpen(_ context.Context, hash TokenHash, now time.Time) (Reset, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	reset, ok := m.resets[hash]
	if !ok || !reset.ExpiresAt.After(now) {
		return Reset{}, ErrInvalidToken
	}
	return reset, nil
}

func (m *memStore) Redeem(ctx context.Context, hash TokenHash, _ users.PasswordHash, now time.Time) (users.User, error) {
	reset, err := m.FindOpen(ctx, hash, now)
	if err != nil {
		return users.User{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.resets, hash)
	for _, account := range m.accounts {
		if account.ID == reset.UserID {
			return account, nil
		}
	}
	return users.User{}, ErrInvalidToken
}

func (m *memStore) Cleanup(context.Context, time.Time) error {
	return nil
}

type memAttempts struct {
	stored []passwordstep.Attempt
}

func (m *memAttempts) Record(_ context.Context, attempt passwordstep.Attempt) error {
	m.stored = append(m.stored, attempt)
	return nil
}

func (m *memAttempts) CountFailures(_ context.Context, _ passwordstep.AttemptKind, login users.Login, ip passwordstep.ClientIP, since time.Time) (passwordstep.RecentFailures, error) {
	var recent passwordstep.RecentFailures
	for _, a := range m.stored {
		if a.AttemptedAt.Before(since) {
			continue
		}
		if a.Login == login {
			recent.Login = passwordstep.FailureCount{Failures: recent.Login.Failures + 1, LastFailure: a.AttemptedAt}
		}
		if a.IP == ip {
			recent.IP = passwordstep.FailureCount{Failures: recent.IP.Failures + 1, LastFailure: a.AttemptedAt}
		}
	}
	return recent, nil
}

func (m *memAttempts) Cleanup(context.Context, time.Time) error {
	return nil
}

type memMailer struct {
	mu   sync.Mutex
	sent []Mail
}

func (m *memMailer) Send(_ context.Context, mail Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

type testLinks struct{}

func (testLinks) ResetLink(token Token) string {
	return "https://id.example.test/recover/" + token.LinkValue()
}

func (testLinks) TokensPage() string { return "https://id.example.test/tokens" }

type serviceFixture struct {
	svc      *Service
	store    *memStore
	attempts *memAttempts
	mailer   *memMailer
	now      time.Time
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	f := &serviceFixture{
		store:    &memStore{accounts: map[users.Login]users.User{}, resets: map[TokenHash]Reset{}},
		attempts: &memAttempts{},
		mailer:   &memMailer{},
		now:      time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
	}
	svc, err := NewService(f.store, f.attempts, f.mailer, testLinks{}, WithClock(func() time.Time { return f.now }))
	require.NoError(t, err)
	f.svc = svc
	return f
}

func (f *serviceFixture) addAccount(t *testing.T, raw string, disabled bool) users.Email {
	t.Helper()
	email, err := users.ParseEmail(raw)
	require.NoError(t, err)
	account := users.User{ID: users.NewID(), Login: email.Login(), CreatedAt: f.now}
	if disabled {
		account.DisabledAt = f.now
	}
	f.store.accounts[email.Login()] = account
	return email
}

// drain runs the queued jobs on the test goroutine.
func (f *serviceFixture) drain(t *testing.T) {
	t.Helper()
	for {
		select {
		case job := <-f.svc.jobs:
			require.NoError(t, job(t.Context()))
		default:
			return
		}
	}
}

func clientIP(t *testing.T, raw string) passwordstep.ClientIP {
	t.Helper()
	ip, err := passwordstep.NewClientIP(netip.MustParseAddr(raw))
	require.NoError(t, err)
	return ip
}

func TestRequestMailsOnlyAnActiveKnownAccount(t *testing.T) {
	f := newServiceFixture(t)
	known := f.addAccount(t, "ada@example.test", false)
	disabled := f.addAccount(t, "bob@example.test", true)
	unknown, err := users.ParseEmail("ghost@example.test")
	require.NoError(t, err)
	ip := clientIP(t, "192.0.2.1")

	for _, email := range []users.Email{unknown, disabled, known} {
		require.NoError(t, f.svc.Request(t.Context(), email, ip))
	}
	f.drain(t)

	require.Len(t, f.mailer.sent, 1)
	mail := f.mailer.sent[0]
	assert.Equal(t, known, mail.To)
	assert.Contains(t, string(mail.Body), "https://id.example.test/recover/")
	assert.Len(t, f.store.resets, 1)
	for _, reset := range f.store.resets {
		assert.Equal(t, f.now.Add(LinkLifetime), reset.ExpiresAt)
	}
}

func TestRequestBackoffPerAddress(t *testing.T) {
	f := newServiceFixture(t)
	email := f.addAccount(t, "ada@example.test", false)
	for i := range passwordstep.FreeFailures {
		ip := clientIP(t, netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}).String())
		require.NoError(t, f.svc.Request(t.Context(), email, ip))
	}
	err := f.svc.Request(t.Context(), email, clientIP(t, "198.51.100.1"))
	var tooSoon *passwordstep.TooSoonError
	require.ErrorAs(t, err, &tooSoon)
	assert.Equal(t, f.now.Add(passwordstep.FirstDelay), tooSoon.RetryAt)
	f.drain(t)
	assert.Len(t, f.mailer.sent, passwordstep.FreeFailures)
}

func TestRequestBackoffPerIP(t *testing.T) {
	f := newServiceFixture(t)
	ip := clientIP(t, "192.0.2.1")
	for i := range passwordstep.FreeFailures {
		email, err := users.ParseEmail("guess" + string(rune('a'+i)) + "@example.test")
		require.NoError(t, err)
		require.NoError(t, f.svc.Request(t.Context(), email, ip))
	}
	email := f.addAccount(t, "ada@example.test", false)
	require.ErrorIs(t, f.svc.Request(t.Context(), email, ip), passwordstep.ErrTooSoon)
}

func TestRequestQueueFull(t *testing.T) {
	f := newServiceFixture(t)
	f.svc.jobs = make(chan mailJob, 1)
	email := f.addAccount(t, "ada@example.test", false)
	require.NoError(t, f.svc.Request(t.Context(), email, clientIP(t, "192.0.2.1")))
	require.ErrorIs(t, f.svc.Request(t.Context(), email, clientIP(t, "192.0.2.2")), ErrQueueFull)
}

func TestResetOnceAndMailsTheChange(t *testing.T) {
	f := newServiceFixture(t)
	email := f.addAccount(t, "ada@example.test", false)
	token, err := NewToken()
	require.NoError(t, err)
	account := f.store.accounts[email.Login()]
	require.NoError(t, f.store.Create(t.Context(), Reset{Hash: token.Hash(), UserID: account.ID, ExpiresAt: f.now.Add(LinkLifetime)}))
	password, err := users.NewPassword("a new password")
	require.NoError(t, err)

	require.NoError(t, f.svc.Check(t.Context(), token))
	require.NoError(t, f.svc.Reset(t.Context(), token, password))
	require.ErrorIs(t, f.svc.Reset(t.Context(), token, password), ErrInvalidToken)
	require.ErrorIs(t, f.svc.Check(t.Context(), token), ErrInvalidToken)
	f.drain(t)
	require.Len(t, f.mailer.sent, 1)
	assert.Equal(t, email, f.mailer.sent[0].To)
	assert.Contains(t, string(f.mailer.sent[0].Body), "https://id.example.test/tokens")
	assert.Contains(t, string(f.mailer.sent[0].Body), "Personal access tokens stay valid")
}

func TestResetRefusesAnExpiredLink(t *testing.T) {
	f := newServiceFixture(t)
	email := f.addAccount(t, "ada@example.test", false)
	token, err := NewToken()
	require.NoError(t, err)
	account := f.store.accounts[email.Login()]
	require.NoError(t, f.store.Create(t.Context(), Reset{Hash: token.Hash(), UserID: account.ID, ExpiresAt: f.now.Add(LinkLifetime)}))
	f.now = f.now.Add(LinkLifetime)
	password, err := users.NewPassword("a new password")
	require.NoError(t, err)
	require.ErrorIs(t, f.svc.Reset(t.Context(), token, password), ErrInvalidToken)
}

func TestRunStopsWithTheContext(t *testing.T) {
	f := newServiceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.svc.Run(ctx, nil)
	}()
	failed := errors.New("relay is down")
	ran := make(chan struct{})
	require.NoError(t, f.svc.enqueue(func(context.Context) error {
		close(ran)
		return failed
	}))
	<-ran
	cancel()
	<-done
}

func TestTokenRoundTripAndRedaction(t *testing.T) {
	token, err := NewToken()
	require.NoError(t, err)
	parsed, err := ParseToken(token.LinkValue())
	require.NoError(t, err)
	assert.Equal(t, token, parsed)
	assert.True(t, parsed.Matches(token.Hash()))
	assert.Equal(t, "redacted", token.String())
	for _, bad := range []string{"", "short", strings.Repeat("A", tokenTextLength), strings.Repeat("!", tokenTextLength)} {
		_, err := ParseToken(bad)
		assert.ErrorIs(t, err, ErrInvalidToken, bad)
	}
}
