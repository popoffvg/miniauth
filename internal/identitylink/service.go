package identitylink

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// LinkTTL is how long a pending link waits for the password login.
const LinkTTL = 15 * time.Minute

// PendingLink is an outside account that waits for a password login in the same browser.
type PendingLink struct {
	Account   users.ExternalAccount
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Store keeps pending links.
// Link MUST, in one transaction, delete the live row of hash and insert an identity of userID
// for its account. A row whose expires_at is at or before now is not live: Link returns ErrNotFound.
// Link MUST return ErrAccountTaken on a unique violation and then delete the row.
// Find returns the live row of hash, else ErrNotFound. Delete deletes the row of hash; a missing row is no error.
// Cleanup deletes the rows that expired at or before now.
type Store interface {
	Insert(ctx context.Context, hash SecretHash, link PendingLink) error
	Find(ctx context.Context, hash SecretHash, now time.Time) (PendingLink, error)
	Link(ctx context.Context, hash SecretHash, userID users.ID, identityID users.IdentityID, now time.Time) (users.ExternalAccount, error)
	Delete(ctx context.Context, hash SecretHash) error
	Cleanup(ctx context.Context, now time.Time) error
}

// Service stores pending links and turns them into identities.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
func NewService(store Store) *Service {
	return &Service{store: store, now: time.Now}
}

// Remember stores account as a pending link and returns the secret for the browser cookie.
// Only the hash of the secret is stored.
func (s *Service) Remember(ctx context.Context, account users.ExternalAccount) (LinkSecret, error) {
	if account.Kind == "" || account.Kind == users.KindPassword || account.Subject == (users.Subject{}) {
		return LinkSecret{}, errors.New("identitylink: account is not an outside account")
	}
	now := s.now().UTC()
	if err := s.store.Cleanup(ctx, now); err != nil {
		return LinkSecret{}, err
	}
	secret, err := NewLinkSecret()
	if err != nil {
		return LinkSecret{}, err
	}
	link := PendingLink{Account: account, CreatedAt: now, ExpiresAt: now.Add(LinkTTL)}
	if err := s.store.Insert(ctx, secret.Hash(), link); err != nil {
		return LinkSecret{}, err
	}
	return secret, nil
}

// Complete makes the pending link of secret an identity of userID and deletes the link.
// An expired or used link is ErrNotFound.
func (s *Service) Complete(ctx context.Context, secret LinkSecret, userID users.ID) (users.ExternalAccount, error) {
	if userID == (users.ID{}) {
		return users.ExternalAccount{}, errors.New("identitylink: user id is empty")
	}
	return s.store.Link(ctx, secret.Hash(), userID, users.NewIdentityID(), s.now().UTC())
}

// Pending returns the live pending link of secret. An expired or used link is ErrNotFound.
func (s *Service) Pending(ctx context.Context, secret LinkSecret) (PendingLink, error) {
	return s.store.Find(ctx, secret.Hash(), s.now().UTC())
}

// Discard deletes the pending link of secret, so it never becomes an identity.
func (s *Service) Discard(ctx context.Context, secret LinkSecret) error {
	return s.store.Delete(ctx, secret.Hash())
}
