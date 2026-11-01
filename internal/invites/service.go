package invites

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

// Store keeps invites.
// Create MUST return groups.ErrGroupNotFound when the group is not stored.
// Find MUST return ErrInviteGone for a hash that is not stored.
// InTransaction runs fn in one database transaction. An error from fn rolls back every write of fn.
type Store interface {
	Create(ctx context.Context, invite Invite) error
	Find(ctx context.Context, hash TokenHash) (Invite, error)
	InTransaction(ctx context.Context, fn func(Transaction) error) error
}

// Transaction is the set of reads and writes of one acceptance.
// Find MUST return ErrInviteGone for a hash that is not stored.
// Claim sets used_at to now only when the invite is unused and expires after now, in one conditional write,
// so two parallel acceptances cannot both claim it. Else it returns ErrInviteGone.
// RecordUser stores the account the acceptance created.
// Users().Create MUST also add the account to groups.Users.
type Transaction interface {
	Find(ctx context.Context, hash TokenHash) (Invite, error)
	Claim(ctx context.Context, hash TokenHash, now time.Time) (Invite, error)
	RecordUser(ctx context.Context, hash TokenHash, user users.ID) error
	Users() users.Repository
	Groups() groups.Writer
}

// Service creates and accepts invites.
type Service struct {
	store  Store
	now    func() time.Time
	logger *slog.Logger
}

// NewService returns a service. A nil now reads the clock from time.Now.
// A nil logger discards the invite transition log.
func NewService(store Store, now func() time.Time, logger *slog.Logger) (*Service, error) {
	if store == nil {
		return nil, errors.New("invites: store is missing")
	}
	if now == nil {
		now = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: store, now: now, logger: logger}, nil
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
// An acceptance that loses a race for the same invite gets an error that wraps ErrInviteGone and sfsm.ErrStaleState.
func (s *Service) Accept(ctx context.Context, token Token, login users.Login, password users.Password) (Acceptance, error) {
	hash := token.Hash()
	now := s.now().UTC()
	var accepted Acceptance
	err := s.store.InTransaction(ctx, func(tx Transaction) error {
		invite, err := tx.Find(ctx, hash)
		if err != nil {
			return err
		}
		if err = s.claim(ctx, tx, invite, now); err != nil {
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

// claim moves invite to StateUsed through the policy. An invite past its expiry gets EventExpire first.
func (s *Service) claim(ctx context.Context, tx Transaction, invite Invite, now time.Time) error {
	record := inviteRecord{tx: tx, read: invite.State(), now: now}
	machine, err := sfsm.OpenPersistedSFSM(ctx, record, invite.Hash, Next, &sfsm.SFSMOptions[InviteState, InviteEvent]{
		AfterStateChanged: func(from, to InviteState, event InviteEvent) {
			s.logger.InfoContext(ctx, "miniauth: invite",
				"group", invite.Group.String(),
				"from", from,
				"to", to,
				"event", event,
			)
		},
	})
	if err != nil {
		return fmt.Errorf("invites: open invite: %w", err)
	}
	defer func() { _ = machine.Close() }()
	if !invite.ExpiresAt.After(now) {
		err = machine.Apply(ctx, EventExpire)
	}
	if err == nil {
		err = machine.Apply(ctx, EventAccept)
	}
	switch {
	case errors.Is(err, ErrNoTransition):
		return ErrInviteGone
	case errors.Is(err, sfsm.ErrStaleState):
		return fmt.Errorf("invites: accept: %w: %w", ErrInviteGone, err)
	case err != nil:
		return fmt.Errorf("invites: accept: %w", err)
	}
	return nil
}

// inviteRecord is the sfsm.Store of one acceptance. Load returns the state the transaction read.
// The conditional claim is the guard: it changes no row when another acceptance claimed the invite first.
type inviteRecord struct {
	tx   Transaction
	read InviteState
	now  time.Time
}

func (r inviteRecord) Load(context.Context, TokenHash) (InviteState, error) {
	return r.read, nil
}

// Write stores nothing for StateExpired: expires_at already decides it.
func (r inviteRecord) Write(ctx context.Context, hash TokenHash, _, next InviteState) error {
	if next != StateUsed {
		return nil
	}
	_, err := r.tx.Claim(ctx, hash, r.now)
	if errors.Is(err, ErrInviteGone) {
		return fmt.Errorf("invites: claim: %w", sfsm.ErrStaleState)
	}
	return err
}
