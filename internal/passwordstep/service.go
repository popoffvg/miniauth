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
// CountFailures counts the failures at or after since. The login count has only attempts of kind,
// and a success of kind resets it. The IP count has every kind and no success resets it,
// so one known account cannot clear the backoff of an IP.
// Cleanup deletes the attempts before before.
type AttemptStore interface {
	Record(ctx context.Context, attempt Attempt) error
	CountFailures(ctx context.Context, kind AttemptKind, login users.Login, ip ClientIP, since time.Time) (RecentFailures, error)
	Cleanup(ctx context.Context, before time.Time) error
}

// Option changes a Service.
type Option func(*Service)

// WithSecondFactors sets EventStepPassed.NeedsSecond for a user that secondFactors reports.
func WithSecondFactors(secondFactors loginflow.SecondFactors) Option {
	return func(s *Service) {
		s.secondFactors = secondFactors
	}
}

// Flow is the login flow that receives the step result. *sfsm.PersistedSFSM from loginflow.LoginFlows.Open fits.
type Flow interface {
	Apply(ctx context.Context, event loginflow.Event) error
}

// Service verifies a password and reports the result to a login flow.
type Service struct {
	identities    IdentityStore
	limiter       *Limiter
	secondFactors loginflow.SecondFactors
	now           func() time.Time
	matches       func(users.PasswordHash, users.Password) (bool, error)
	// unknownLoginHash has the same argon2id cost as a stored hash.
	// An unknown login is verified against it, so the reply takes as long as for a known login.
	unknownLoginHash users.PasswordHash
}

// NewService returns a service that reads the clock from time.Now.
func NewService(identities IdentityStore, attempts AttemptStore, options ...Option) (*Service, error) {
	if identities == nil || attempts == nil {
		return nil, errors.New("passwordstep: store is missing")
	}
	limiter, err := NewLimiter(attempts, KindPassword)
	if err != nil {
		return nil, err
	}
	password, err := users.NewPassword(rand.Text())
	if err != nil {
		return nil, fmt.Errorf("passwordstep: unknown login hash: %w", err)
	}
	hash, err := users.HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("passwordstep: unknown login hash: %w", err)
	}
	s := &Service{
		identities:       identities,
		limiter:          limiter,
		now:              time.Now,
		matches:          users.PasswordHash.Matches,
		unknownLoginHash: hash,
	}
	for _, option := range options {
		option(s)
	}
	return s, nil
}

// Verify checks password for login and sends EventStepPassed or EventStepFailed to flow.
// It returns the user id when the password matches, ErrWrongCredentials when it does not,
// and a *TooSoonError without a check while the backoff of the login or of ip lasts.
func (s *Service) Verify(ctx context.Context, flow Flow, login users.Login, password users.Password, ip ClientIP) (users.ID, error) {
	now := s.now().UTC()
	if err := s.limiter.Wait(ctx, login, ip, now); err != nil {
		return users.ID{}, err
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
	if err = s.limiter.Record(ctx, login, ip, passed, now); err != nil {
		return users.ID{}, err
	}
	event := loginflow.Event{Kind: loginflow.EventStepFailed, Factor: loginflow.FactorPassword}
	if passed {
		if event, err = loginflow.Passed(ctx, s.secondFactors, loginflow.FactorPassword, identity.UserID); err != nil {
			return users.ID{}, err
		}
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
