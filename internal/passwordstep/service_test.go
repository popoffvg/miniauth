package passwordstep

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

type fakeIdentities map[users.Login]users.Identity

func (f fakeIdentities) FindPasswordIdentity(_ context.Context, login users.Login) (users.Identity, error) {
	identity, ok := f[login]
	if !ok {
		return users.Identity{}, users.ErrNotFound
	}
	return identity, nil
}

type fakeAttempts struct {
	stored []Attempt
}

func (f *fakeAttempts) Record(_ context.Context, attempt Attempt) error {
	f.stored = append(f.stored, attempt)
	return nil
}

func (f *fakeAttempts) CountFailures(_ context.Context, kind AttemptKind, login users.Login, ip ClientIP, since time.Time) (RecentFailures, error) {
	var recent RecentFailures
	for _, a := range f.stored {
		if a.AttemptedAt.Before(since) {
			continue
		}
		if a.Login == login && a.Kind == kind {
			if a.Succeeded {
				recent.Login = FailureCount{}
			} else {
				recent.Login = FailureCount{Failures: recent.Login.Failures + 1, LastFailure: a.AttemptedAt}
			}
		}
		if a.IP == ip && !a.Succeeded {
			recent.IP = FailureCount{Failures: recent.IP.Failures + 1, LastFailure: a.AttemptedAt}
		}
	}
	return recent, nil
}

func (f *fakeAttempts) Cleanup(context.Context, time.Time) error {
	return nil
}

type fakeFlow struct {
	events []loginflow.Event
	err    error
}

func (f *fakeFlow) Apply(_ context.Context, event loginflow.Event) error {
	f.events = append(f.events, event)
	return f.err
}

// stepFixture runs the service on a fake clock and counts every argon2id verify.
type stepFixture struct {
	svc      *Service
	attempts *fakeAttempts
	now      time.Time
	verified []users.PasswordHash
	user     users.Identity
	login    users.Login
	password users.Password
}

func newStepFixture(t *testing.T) *stepFixture {
	t.Helper()
	login := mustLogin(t, "ada")
	password, err := users.NewPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	hash, err := users.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	user := users.Identity{ID: users.NewIdentityID(), UserID: users.NewID(), Kind: users.KindPassword, Secret: hash}
	f := &stepFixture{
		attempts: &fakeAttempts{},
		now:      time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC),
		user:     user,
		login:    login,
		password: password,
	}
	svc, err := NewService(fakeIdentities{login: user}, f.attempts)
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return f.now }
	svc.matches = func(h users.PasswordHash, p users.Password) (bool, error) {
		f.verified = append(f.verified, h)
		return h.Matches(p)
	}
	f.svc = svc
	return f
}

func (f *stepFixture) verify(t *testing.T, login users.Login, password users.Password, ip ClientIP) (users.ID, *fakeFlow, error) {
	t.Helper()
	flow := &fakeFlow{}
	id, err := f.svc.Verify(t.Context(), flow, login, password, ip)
	return id, flow, err
}

func (f *stepFixture) wrongPassword(t *testing.T) users.Password {
	t.Helper()
	p, err := users.NewPassword("wrong password")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyRightPassword(t *testing.T) {
	f := newStepFixture(t)
	ip := mustIP(t, "192.0.2.1")
	id, flow, err := f.verify(t, f.login, f.password, ip)
	if err != nil {
		t.Fatal(err)
	}
	if id != f.user.UserID {
		t.Fatalf("Verify() = %s, want %s", id, f.user.UserID)
	}
	want := loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorPassword, UserID: f.user.UserID}
	assertEvents(t, flow, want)
	assertVerifies(t, f, 1)
	assertLastAttempt(t, f, Attempt{Kind: KindPassword, Login: f.login, IP: ip, Succeeded: true, AttemptedAt: f.now})
}

type fakeSecondFactors map[users.ID]bool

func (f fakeSecondFactors) HasSecondFactor(_ context.Context, userID users.ID) (bool, error) {
	return f[userID], nil
}

func TestVerifyRightPasswordOfAUserWithTOTPNeedsASecondStep(t *testing.T) {
	f := newStepFixture(t)
	WithSecondFactors(fakeSecondFactors{f.user.UserID: true})(f.svc)
	_, flow, err := f.verify(t, f.login, f.password, mustIP(t, "192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	want := loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorPassword, UserID: f.user.UserID, NeedsSecond: true}
	assertEvents(t, flow, want)
}

func TestVerifyWrongPassword(t *testing.T) {
	f := newStepFixture(t)
	ip := mustIP(t, "192.0.2.1")
	id, flow, err := f.verify(t, f.login, f.wrongPassword(t), ip)
	if !errors.Is(err, ErrWrongCredentials) {
		t.Fatalf("Verify() error = %v, want ErrWrongCredentials", err)
	}
	if id != (users.ID{}) {
		t.Fatalf("Verify() id = %s on a failure", id)
	}
	assertEvents(t, flow, loginflow.Event{Kind: loginflow.EventStepFailed, Factor: loginflow.FactorPassword})
	assertVerifies(t, f, 1)
	assertLastAttempt(t, f, Attempt{Kind: KindPassword, Login: f.login, IP: ip, Succeeded: false, AttemptedAt: f.now})
}

func TestVerifyUnknownLoginRunsOneArgon2idVerify(t *testing.T) {
	f := newStepFixture(t)
	ip := mustIP(t, "192.0.2.1")
	ghost := mustLogin(t, " Ghost ")
	_, flow, err := f.verify(t, ghost, f.password, ip)
	if !errors.Is(err, ErrWrongCredentials) {
		t.Fatalf("Verify() error = %v, want ErrWrongCredentials", err)
	}
	assertEvents(t, flow, loginflow.Event{Kind: loginflow.EventStepFailed, Factor: loginflow.FactorPassword})
	assertVerifies(t, f, 1)
	if got, want := argonParams(t, f.verified[0]), argonParams(t, f.user.Secret); got != want {
		t.Fatalf("unknown login hash parameters %q, stored hash parameters %q", got, want)
	}
	assertLastAttempt(t, f, Attempt{Kind: KindPassword, Login: mustLogin(t, "ghost"), IP: ip, Succeeded: false, AttemptedAt: f.now})
}

func TestVerifyBackoffPerLogin(t *testing.T) {
	f := newStepFixture(t)
	for i := range FreeFailures {
		f.now = f.now.Add(time.Second)
		_, _, err := f.verify(t, f.login, f.wrongPassword(t), mustIP(t, fmt.Sprintf("192.0.2.%d", i+1)))
		if !errors.Is(err, ErrWrongCredentials) {
			t.Fatalf("failure %d error = %v", i+1, err)
		}
	}
	assertBackoff(t, f, f.login, mustIP(t, "198.51.100.1"))
}

func TestVerifyBackoffPerIP(t *testing.T) {
	f := newStepFixture(t)
	ip := mustIP(t, "2001:db8:0:1::1")
	for i := range FreeFailures {
		f.now = f.now.Add(time.Second)
		_, _, err := f.verify(t, mustLogin(t, fmt.Sprintf("guess%d", i)), f.wrongPassword(t), ip)
		if !errors.Is(err, ErrWrongCredentials) {
			t.Fatalf("failure %d error = %v", i+1, err)
		}
	}
	// Another address in the same /64 is the same client.
	assertBackoff(t, f, f.login, mustIP(t, "2001:db8:0:1::2"))
}

// assertBackoff expects FreeFailures failures, the last at f.now, that count for login or ip.
func assertBackoff(t *testing.T, f *stepFixture, login users.Login, ip ClientIP) {
	t.Helper()
	last := f.now
	verifies := len(f.verified)
	recorded := len(f.attempts.stored)

	_, flow, err := f.verify(t, login, f.password, ip)
	assertTooSoon(t, err, last.Add(time.Second))
	assertEvents(t, flow)
	assertVerifies(t, f, verifies)
	if len(f.attempts.stored) != recorded {
		t.Fatal("a refused try was recorded")
	}

	f.now = last.Add(time.Second)
	_, _, err = f.verify(t, login, f.wrongPassword(t), ip)
	if !errors.Is(err, ErrWrongCredentials) {
		t.Fatalf("try after the wait error = %v", err)
	}

	f.now = f.now.Add(time.Second)
	_, _, err = f.verify(t, login, f.password, ip)
	assertTooSoon(t, err, last.Add(3*time.Second))

	f.now = last.Add(3 * time.Second)
	_, _, err = f.verify(t, login, f.password, ip)
	if err != nil {
		t.Fatalf("right password after the wait error = %v", err)
	}
}

func TestVerifyFlowError(t *testing.T) {
	f := newStepFixture(t)
	flow := &fakeFlow{err: loginflow.ErrNoTransition}
	_, err := f.svc.Verify(t.Context(), flow, f.login, f.password, mustIP(t, "192.0.2.1"))
	if !errors.Is(err, loginflow.ErrNoTransition) {
		t.Fatalf("Verify() error = %v, want ErrNoTransition", err)
	}
}

func TestVerifyRefusesZeroValues(t *testing.T) {
	f := newStepFixture(t)
	if _, _, err := f.verify(t, users.Login{}, f.password, mustIP(t, "192.0.2.1")); !errors.Is(err, users.ErrInvalidLogin) {
		t.Fatalf("zero login error = %v", err)
	}
	if _, _, err := f.verify(t, f.login, f.password, ClientIP{}); !errors.Is(err, ErrInvalidClientIP) {
		t.Fatalf("zero IP error = %v", err)
	}
	assertVerifies(t, f, 0)
}

func assertTooSoon(t *testing.T, err error, retryAt time.Time) {
	t.Helper()
	var tooSoon *TooSoonError
	if !errors.As(err, &tooSoon) || !errors.Is(err, ErrTooSoon) {
		t.Fatalf("error = %v, want *TooSoonError", err)
	}
	if !tooSoon.RetryAt.Equal(retryAt) {
		t.Fatalf("RetryAt = %s, want %s", tooSoon.RetryAt, retryAt)
	}
}

func assertEvents(t *testing.T, flow *fakeFlow, want ...loginflow.Event) {
	t.Helper()
	if len(flow.events) != len(want) {
		t.Fatalf("events = %+v, want %+v", flow.events, want)
	}
	for i := range want {
		if flow.events[i] != want[i] {
			t.Fatalf("event %d = %+v, want %+v", i, flow.events[i], want[i])
		}
	}
}

func assertVerifies(t *testing.T, f *stepFixture, want int) {
	t.Helper()
	if len(f.verified) != want {
		t.Fatalf("argon2id verifies = %d, want %d", len(f.verified), want)
	}
}

func assertLastAttempt(t *testing.T, f *stepFixture, want Attempt) {
	t.Helper()
	if len(f.attempts.stored) == 0 {
		t.Fatal("no attempt recorded")
	}
	if got := f.attempts.stored[len(f.attempts.stored)-1]; got != want {
		t.Fatalf("attempt = %+v, want %+v", got, want)
	}
}

// argonParams returns the version and cost fields of a PHC string.
func argonParams(t *testing.T, hash users.PasswordHash) string {
	t.Helper()
	parts := strings.Split(hash.Encoded(), "$")
	if len(parts) != 6 {
		t.Fatalf("hash has %d PHC fields", len(parts))
	}
	return strings.Join(parts[1:4], "$")
}

func mustLogin(t *testing.T, raw string) users.Login {
	t.Helper()
	login, err := users.ParseLogin(raw)
	if err != nil {
		t.Fatal(err)
	}
	return login
}

func mustIP(t *testing.T, raw string) ClientIP {
	t.Helper()
	ip, err := NewClientIP(netip.MustParseAddr(raw))
	if err != nil {
		t.Fatal(err)
	}
	return ip
}
