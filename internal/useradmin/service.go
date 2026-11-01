package useradmin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Store keeps the accounts.
// ListAccounts returns every user in login order.
// Write stores the transition from prev to next. It MUST wrap sfsm.ErrStaleState when the stored status is no longer prev.Status.
// A write to StatusDisabled MUST also delete every session of the user in the same transaction.
// AddMember MUST return ErrUserNotFound for a user that is not stored.
// AddMember MUST return groups.ErrGroupNotFound for a group that is not stored. AddMember of a pair that is stored changes nothing. RemoveMember MUST return ErrNotMember when the pair is not stored.
type Store interface {
	ListAccounts(ctx context.Context) ([]Account, error)
	Write(ctx context.Context, id users.ID, prev, next AccountState) error
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
	logger   *slog.Logger
}

// NewService reads the clock from time.Now. A nil logger discards the account transition log.
func NewService(store Store, accounts accountFinder, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: store, accounts: accounts, now: time.Now, logger: logger}
}

// List returns every account, a disabled one too.
func (s *Service) List(ctx context.Context) ([]Account, error) {
	return s.store.ListAccounts(ctx)
}

// Disable signs the user out everywhere and refuses every next login of the user.
// A user who is disabled already stays as is and keeps the first disabled time.
func (s *Service) Disable(ctx context.Context, actor Actor, login users.Login) error {
	return s.transition(ctx, login, AccountEvent{Kind: EventDisable, Actor: actor, At: s.now()})
}

// Enable lets the user sign in again. A user who is not disabled stays as is.
func (s *Service) Enable(ctx context.Context, actor Actor, login users.Login) error {
	return s.transition(ctx, login, AccountEvent{Kind: EventEnable, Actor: actor})
}

// transition applies event to the stored user. ErrNoTransition is the target status already, so it is nil.
// A lost race with another change of the same user is an error that wraps sfsm.ErrStaleState.
func (s *Service) transition(ctx context.Context, login users.Login, event AccountEvent) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	record := accountRecord{store: s.store, read: accountStateOf(user)}
	machine, err := sfsm.OpenPersistedSFSM(ctx, record, user.ID, Next, &sfsm.SFSMOptions[AccountState, AccountEvent]{
		AfterStateChanged: func(from, to AccountState, event AccountEvent) {
			s.logger.InfoContext(ctx, "miniauth: user account",
				"user", to.User,
				"actor", event.Actor.ID,
				"from", from.Status,
				"to", to.Status,
				"event", event.Kind,
			)
		},
	})
	if err != nil {
		return fmt.Errorf("useradmin: open account: %w", err)
	}
	defer func() { _ = machine.Close() }()
	err = machine.Apply(ctx, event)
	switch {
	case errors.Is(err, ErrNoTransition):
		return nil
	case err != nil:
		return fmt.Errorf("useradmin: %s: %w", event.Kind, err)
	}
	return nil
}

// accountRecord is the sfsm.Store of one change. Load returns the state the service read.
// The status guard of Write refuses the change when another request moved the user after that read.
type accountRecord struct {
	store Store
	read  AccountState
}

func (r accountRecord) Load(context.Context, users.ID) (AccountState, error) {
	return r.read, nil
}

func (r accountRecord) Write(ctx context.Context, id users.ID, prev, next AccountState) error {
	return r.store.Write(ctx, id, prev, next)
}

// AddToGroup keeps a stored membership as it is.
func (s *Service) AddToGroup(ctx context.Context, login users.Login, name groups.Name) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	return s.store.AddMember(ctx, user.ID, name)
}

// RemoveFromGroup refuses to take the actor out of groups.Admins, so the last admin cannot lock all admins out by mistake.
func (s *Service) RemoveFromGroup(ctx context.Context, actor Actor, login users.Login, name groups.Name) error {
	user, err := s.find(ctx, login)
	if err != nil {
		return err
	}
	if actor.ID == user.ID && name == groups.Admins() {
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
