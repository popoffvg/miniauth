package passwordstep

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// IdentityStore finds the password identity of a login.
// FindPasswordIdentity MUST return users.ErrNotFound when no user has the login.
type IdentityStore interface {
	FindPasswordIdentity(ctx context.Context, login users.Login) (users.Identity, error)
}

// AttemptStore keeps login attempts.
// CountFailures counts the failures at or after since. A success resets the login count,
// not the IP count, so one known account cannot clear the backoff of an IP.
// Cleanup deletes the attempts before before.
type AttemptStore interface {
	Record(ctx context.Context, attempt Attempt) error
	CountFailures(ctx context.Context, login users.Login, ip ClientIP, since time.Time) (RecentFailures, error)
	Cleanup(ctx context.Context, before time.Time) error
}

// Flow is the login flow that receives the step result. *sfsm.PersistedSFSM from loginflow.LoginFlows.Open fits.
type Flow interface {
	Apply(ctx context.Context, event loginflow.Event) error
}

// Service verifies a password and reports the result to a login flow.
type Service struct {
	identities IdentityStore
	attempts   AttemptStore
	now        func() time.Time
	matches    func(users.PasswordHash, users.Password) (bool, error)
	// unknownLoginHash has the same argon2id cost as a stored hash.
	// An unknown login is verified against it, so the reply takes as long as for a known login.
	unknownLoginHash users.PasswordHash
}

// NewService returns a service that reads the clock from time.Now.
func NewService(identities IdentityStore, attempts AttemptStore) (*Service, error) {
	if identities == nil || attempts == nil {
		return nil, errors.New("passwordstep: store is missing")
	}
	password, err := users.NewPassword(rand.Text())
	if err != nil {
		return nil, fmt.Errorf("passwordstep: unknown login hash: %w", err)
	}
	hash, err := users.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("passwordstep: unknown login hash: %w", err)
	}
	return &Service{
		identities:       identities,
		attempts:         attempts,
		now:              time.Now,
		matches:          users.PasswordHash.Matches,
		unknownLoginHash: hash,
	}, nil
}

// Verify checks password for login and sends EventStepPassed or EventStepFailed to flow.
// It returns the user id when the password matches, ErrWrongCredentials when it does not,
// and a *TooSoonError without a check while the backoff of the login or of ip lasts.
func (s *Service) Verify(ctx context.Context, flow Flow, login users.Login, password users.Password, ip ClientIP) (users.ID, error) {
	if login == (users.Login{}) {
		return users.ID{}, users.ErrInvalidLogin
	}
	if ip == (ClientIP{}) {
		return users.ID{}, ErrInvalidClientIP
	}
	now := s.now().UTC()
	since := now.Add(-BackoffWindow)
	if err := s.attempts.Cleanup(ctx, since); err != nil {
		return users.ID{}, err
	}
	recent, err := s.attempts.CountFailures(ctx, login, ip, since)
	if err != nil {
		return users.ID{}, err
	}
	if retryAt := recent.ReadyAt(); now.Before(retryAt) {
		return users.ID{}, &TooSoonError{RetryAt: retryAt}
	}
	identity, known, err := s.findIdentity(ctx, login)
	if err != nil {
		return users.ID{}, err
	}
	matched, err := s.matches(identity.Secret, password)
	if err != nil {
		return users.ID{}, err
	}
	passed := known && matched
	attempt := Attempt{Login: login, IP: ip, Succeeded: passed, AttemptedAt: now}
	if err := s.attempts.Record(ctx, attempt); err != nil {
		return users.ID{}, err
	}
	event := loginflow.Event{Kind: loginflow.EventStepFailed, Factor: loginflow.FactorPassword}
	if passed {
		event.Kind = loginflow.EventStepPassed
	}
	if err := flow.Apply(ctx, event); err != nil {
		return users.ID{}, fmt.Errorf("passwordstep: apply %s: %w", event.Kind, err)
	}
	if !passed {
		return users.ID{}, ErrWrongCredentials
	}
	return identity.UserID, nil
}

// findIdentity returns unknownLoginHash as the secret when no user has the login.
func (s *Service) findIdentity(ctx context.Context, login users.Login) (users.Identity, bool, error) {
	identity, err := s.identities.FindPasswordIdentity(ctx, login)
	if errors.Is(err, users.ErrNotFound) {
		return users.Identity{Secret: s.unknownLoginHash}, false, nil
	}
	if err != nil {
		return users.Identity{}, false, err
	}
	return identity, true, nil
}
