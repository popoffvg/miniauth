package useradmin

import (
	"context"
	"errors"
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Store keeps the accounts.
// ListAccounts returns every user in login order.
// Disable MUST set the disabled time and delete every session of the user in one transaction.
// Disable, Enable, and AddMember MUST return ErrUserNotFound for a user that is not stored.
// AddMember of a pair that is stored changes nothing. RemoveMember MUST return ErrNotMember when the pair is not stored.
type Store interface {
	ListAccounts(ctx context.Context) ([]Account, error)
	Disable(ctx context.Context, id users.ID, at time.Time) error
	Enable(ctx context.Context, id users.ID) error
	AddMember(ctx context.Context, id users.ID, name groups.Name) error
	RemoveMember(ctx context.Context, id users.ID, name groups.Name) error
}

// accountFinder reads one user by login. *users.Service fits.
type accountFinder interface {
	FindByLogin(ctx context.Context, login users.Login) (users.User, error)
}

// Actor is the administrator who asks for a change. The zero Actor is the bootstrap admin token:
// it is no user, so no self rule applies.
type Actor struct {
	ID users.ID
}

// Service changes accounts by login.
type Service struct {
	store    Store
	accounts accountFinder
	now      func() time.Time
}

// NewService reads the clock from time.Now.
func NewService(store Store, accounts accountFinder) *Service {
	return &Service{store: store, accounts: accounts, now: time.Now}
}

// List returns every account, a disabled one too.
func (s *Service) List(ctx context.Context) ([]Account, error) {
	return s.store.ListAccounts(ctx)
}

// Disable signs the user out everywhere and refuses every next login of the user.
func (s *Service) Disable(ctx context.Context, actor Actor, login users.Login) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	if actor.ID == user.ID {
		return ErrSelfDisable
	}
	return s.store.Disable(ctx, user.ID, s.now())
}

// Enable lets the user sign in again. A user who is not disabled stays as is.
func (s *Service) Enable(ctx context.Context, login users.Login) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	return s.store.Enable(ctx, user.ID)
}

// AddToGroup keeps a stored membership as it is.
func (s *Service) AddToGroup(ctx context.Context, login users.Login, name groups.Name) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	return s.store.AddMember(ctx, user.ID, name)
}

// RemoveFromGroup refuses to take the actor out of groups.Admin, so the last admin cannot lock all admins out by mistake.
func (s *Service) RemoveFromGroup(ctx context.Context, actor Actor, login users.Login, name groups.Name) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	if actor.ID == user.ID && name == groups.Admin() {
		return ErrSelfAdmin
	}
	return s.store.RemoveMember(ctx, user.ID, name)
}

func (s *Service) find(ctx context.Context, login users.Login) (users.User, error) {
	user, err := s.accounts.FindByLogin(ctx, login)
	if errors.Is(err, users.ErrNotFound) {
		return users.User{}, ErrUserNotFound
	}
	return user, err
}
