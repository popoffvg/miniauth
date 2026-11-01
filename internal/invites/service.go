package invites

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Store keeps invites.
// Create MUST return groups.ErrGroupNotFound when the group is not stored.
// Find MUST return ErrInviteGone for a hash that is not stored.
// InTransaction runs fn in one database transaction. An error from fn rolls back every write of fn.
type Store interface {
	Create(ctx context.Context, invite Invite) error
	Find(ctx context.Context, hash TokenHash) (Invite, error)
	InTransaction(ctx context.Context, fn func(Transaction) error) error
}

// Transaction is the set of writes of one acceptance.
// Claim sets used_at to now only when the invite is unused and expires after now, in one conditional write,
// so two parallel acceptances cannot both claim it. Else it returns ErrInviteGone.
// RecordUser stores the account the acceptance created.
// Users().Create MUST also add the account to groups.Users.
type Transaction interface {
	Claim(ctx context.Context, hash TokenHash, now time.Time) (Invite, error)
	RecordUser(ctx context.Context, hash TokenHash, user users.ID) error
	Users() users.Repository
	Groups() groups.Writer
}

// Service creates and accepts invites.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService returns a service. A nil now reads the clock from time.Now.
func NewService(store Store, now func() time.Time) (*Service, error) {
	if store == nil {
		return nil, errors.New("invites: store is missing")
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}, nil
}

// Create stores an invite to the group and returns its token. A zero group is groups.Users.
// The token is not stored, so the caller can show it only once.
func (s *Service) Create(ctx context.Context, group groups.Name) (Token, Invite, error) {
	if group == (groups.Name{}) {
		group = groups.Users()
	}
	token, err := NewToken()
	if err != nil {
		return Token{}, Invite{}, err
	}
	now := s.now().UTC()
	invite := Invite{
		Hash:      token.Hash(),
		Group:     group,
		CreatedAt: now,
		ExpiresAt: now.Add(Lifetime),
	}
	if err := s.store.Create(ctx, invite); err != nil {
		return Token{}, Invite{}, err
	}
	return token, invite, nil
}

// Open returns the invite of token when it is unused and not expired. Else it returns ErrInviteGone.
func (s *Service) Open(ctx context.Context, token Token) (Invite, error) {
	invite, err := s.store.Find(ctx, token.Hash())
	if err != nil {
		return Invite{}, err
	}
	if !invite.OpenAt(s.now()) {
		return Invite{}, ErrInviteGone
	}
	return invite, nil
}

// Accept claims the invite and creates the account with a password identity in the group of the invite.
// The writes are one transaction. A used or expired invite is ErrInviteGone.
// A taken login is users.ErrLoginTaken, and the invite stays unused.
func (s *Service) Accept(ctx context.Context, token Token, login users.Login, password users.Password) (Acceptance, error) {
	hash := token.Hash()
	now := s.now().UTC()
	var accepted Acceptance
	err := s.store.InTransaction(ctx, func(tx Transaction) error {
		invite, err := tx.Claim(ctx, hash, now)
		if err != nil {
			return err
		}
		account, err := users.NewService(tx.Users()).Create(ctx, login, password)
		if err != nil {
			return err
		}
		if err = tx.RecordUser(ctx, hash, account.ID); err != nil {
			return err
		}
		if invite.Group != groups.Users() {
			if err = tx.Groups().Add(ctx, account.ID, invite.Group); err != nil {
				return err
			}
		}
		accepted = Acceptance{User: account, Group: invite.Group}
		return nil
	})
	if err != nil {
		return Acceptance{}, err
	}
	return accepted, nil
}
