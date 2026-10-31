package tokens

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// Repository stores tokens.
// Create stores the hash, never the clear token.
// Create MUST return ErrDuplicate when the hash is already stored, and ErrUnknownUser for an unknown user.
// Find MUST return ErrInvalid when no token has the hash.
// Revoke MUST return ErrNotFound when the user has no token with the id.
// Touch writes last_used_at only when the stored value is empty or at or before touchBefore.
type Repository interface {
	Create(ctx context.Context, token Token, hash Hash) error
	Find(ctx context.Context, hash Hash) (Token, Hash, error)
	List(ctx context.Context, userID users.ID) ([]Token, error)
	Revoke(ctx context.Context, userID users.ID, id ID, at time.Time) error
	Touch(ctx context.Context, id ID, at, touchBefore time.Time) error
}

// Service issues, lists, revokes, and checks tokens.
type Service struct {
	repo Repository
	now  func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
func NewService(repo Repository) *Service {
	return &Service{repo: repo, now: time.Now}
}

// Issue stores a new token and returns its clear form.
// The clear form is not stored, so this is the only call that returns it.
// A zero expiresAt never expires.
func (s *Service) Issue(ctx context.Context, userID users.ID, name Name, scopes Scopes, expiresAt time.Time) (Secret, Token, error) {
	secret, err := NewSecret()
	if err != nil {
		return Secret{}, Token{}, err
	}
	token, err := s.store(ctx, userID, name, scopes, expiresAt, secret)
	if err != nil {
		return Secret{}, Token{}, err
	}
	return secret, token, nil
}

// Import stores a clear token that was made outside this service.
// The imported token does not expire.
// When userID already has the token, Import returns the stored token, created is false, and nothing changes.
// When another user has the token, Import returns ErrDuplicate.
func (s *Service) Import(ctx context.Context, userID users.ID, name Name, scopes Scopes, secret Secret) (token Token, created bool, err error) {
	if _, err = ParseSecret(secret.raw); err != nil {
		return Token{}, false, err
	}
	token, err = s.store(ctx, userID, name, scopes, time.Time{}, secret)
	if !errors.Is(err, ErrDuplicate) {
		return token, err == nil, err
	}
	stored, hash, err := s.repo.Find(ctx, secret.Hash())
	if err != nil {
		return Token{}, false, err
	}
	if !secret.Matches(hash) || stored.UserID != userID {
		return Token{}, false, ErrDuplicate
	}
	return stored, false, nil
}

// List returns every token of the user, revoked and expired ones included.
func (s *Service) List(ctx context.Context, userID users.ID) ([]Token, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.repo.List(ctx, userID)
}

// Revoke ends the token. A token revoked before keeps its first revoked_at.
func (s *Service) Revoke(ctx context.Context, userID users.ID, id ID) error {
	if err := s.ready(); err != nil {
		return err
	}
	return s.repo.Revoke(ctx, userID, id, s.clock())
}

// Authenticate returns the token for secret.
// A revoked or expired token is ErrInvalid. It does not check the owner account.
// last_used_at is written at most once per UseEvery.
func (s *Service) Authenticate(ctx context.Context, secret Secret) (Token, error) {
	if err := s.ready(); err != nil {
		return Token{}, err
	}
	if secret.raw == "" {
		return Token{}, ErrInvalid
	}
	token, stored, err := s.repo.Find(ctx, secret.Hash())
	if err != nil {
		return Token{}, err
	}
	now := s.clock()
	if !secret.Matches(stored) || token.Revoked() || token.Expired(now) {
		return Token{}, ErrInvalid
	}
	if token.usedRecently(now) {
		return token, nil
	}
	if err := s.repo.Touch(ctx, token.ID, now, now.Add(-UseEvery)); err != nil {
		return Token{}, err
	}
	token.LastUsedAt = now
	return token, nil
}

func (s *Service) store(ctx context.Context, userID users.ID, name Name, scopes Scopes, expiresAt time.Time, secret Secret) (Token, error) {
	if err := s.ready(); err != nil {
		return Token{}, err
	}
	if userID == (users.ID{}) {
		return Token{}, ErrUnknownUser
	}
	if name.value == "" {
		return Token{}, ErrName
	}
	for _, scope := range scopes {
		if scope.scheme == "" {
			return Token{}, ErrScope
		}
	}
	now := s.clock()
	if !expiresAt.IsZero() && !expiresAt.After(now) {
		return Token{}, ErrExpiry
	}
	if !expiresAt.IsZero() {
		expiresAt = expiresAt.UTC().Truncate(time.Microsecond)
	}
	token := Token{
		ID:        NewID(),
		UserID:    userID,
		Prefix:    secret.Prefix(),
		Name:      name,
		Scopes:    scopes,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	if err := s.repo.Create(ctx, token, secret.Hash()); err != nil {
		return Token{}, err
	}
	return token, nil
}

func (s *Service) ready() error {
	if s == nil || s.repo == nil {
		return errors.New("tokens: repository is missing")
	}
	return nil
}

// clock returns UTC truncated to microseconds.
// PostgreSQL timestamptz stores microseconds.
func (s *Service) clock() time.Time {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	return now().UTC().Truncate(time.Microsecond)
}
