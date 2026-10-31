package passwordstep

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// Limiter is the backoff of one AttemptKind. A step calls Wait before it checks a secret, then Record.
type Limiter struct {
	attempts AttemptStore
	kind     AttemptKind
}

// NewLimiter returns the backoff of kind on attempts.
func NewLimiter(attempts AttemptStore, kind AttemptKind) (*Limiter, error) {
	if attempts == nil {
		return nil, errors.New("passwordstep: attempt store is missing")
	}
	return &Limiter{attempts: attempts, kind: kind}, nil
}

// Wait returns a *TooSoonError while the backoff of login or of ip lasts at now.
func (l *Limiter) Wait(ctx context.Context, login users.Login, ip ClientIP, now time.Time) error {
	if login == (users.Login{}) {
		return users.ErrInvalidLogin
	}
	if ip == (ClientIP{}) {
		return ErrInvalidClientIP
	}
	since := now.Add(-BackoffWindow)
	if err := l.attempts.Cleanup(ctx, since); err != nil {
		return err
	}
	recent, err := l.attempts.CountFailures(ctx, l.kind, login, ip, since)
	if err != nil {
		return err
	}
	if retryAt := recent.ReadyAt(); now.Before(retryAt) {
		return &TooSoonError{RetryAt: retryAt}
	}
	return nil
}

// Record stores the result of one try at now.
func (l *Limiter) Record(ctx context.Context, login users.Login, ip ClientIP, succeeded bool, now time.Time) error {
	return l.attempts.Record(ctx, Attempt{Kind: l.kind, Login: login, IP: ip, Succeeded: succeeded, AttemptedAt: now})
}
