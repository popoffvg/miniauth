package telegramstep

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// MaxAge is how long widget data stays valid after its auth_date.
	MaxAge = 24 * time.Hour
	// MaxClockSkew is how far in the future an auth_date can be.
	MaxClockSkew = time.Minute
)

// IdentityStore finds the identity of an outside account.
// FindExternalIdentity MUST return users.ErrNotFound for an unknown account or a disabled user.
type IdentityStore interface {
	FindExternalIdentity(ctx context.Context, account users.ExternalAccount) (users.Identity, error)
}

// ProofStore remembers each accepted widget login.
// Use MUST store hash and return ErrReplay when hash is already stored.
// Cleanup deletes the rows that expired at or before now.
type ProofStore interface {
	Use(ctx context.Context, hash ProofHash, expiresAt time.Time) error
	Cleanup(ctx context.Context, now time.Time) error
}

// Flow is the login flow that receives the step result. *sfsm.PersistedSFSM from loginflow.LoginFlows.Open fits.
type Flow interface {
	Apply(ctx context.Context, event loginflow.Event) error
}

// Outcome is the result of valid widget data.
// UserID is set for a linked account. Otherwise Unlinked is the account that waits for a link.
type Outcome struct {
	UserID   users.ID
	Unlinked users.ExternalAccount
}

// Linked reports whether the account belongs to a user.
func (o Outcome) Linked() bool {
	return o.UserID != (users.ID{})
}

// Step checks the widget data of one bot.
type Step struct {
	botName    BotName
	key        [sha256.Size]byte
	identities IdentityStore
	proofs     ProofStore
	now        func() time.Time
}

// NewStep returns a step for the bot in config.
func NewStep(config Config, identities IdentityStore, proofs ProofStore) (*Step, error) {
	if config.BotName == (BotName{}) || config.BotToken.Empty() {
		return nil, ErrConfig
	}
	if identities == nil || proofs == nil {
		return nil, errors.New("telegramstep: store is missing")
	}
	return &Step{
		botName:    config.BotName,
		key:        sha256.Sum256([]byte(config.BotToken.value)),
		identities: identities,
		proofs:     proofs,
		now:        time.Now,
	}, nil
}

// BotName is the bot that the widget shows.
func (s *Step) BotName() BotName {
	return s.botName
}

// Finish checks data and sends EventStepPassed with FactorTelegram to flow.
// The hash and the age are checked first. Then the proof of data is stored, so the same data passes once.
// A known account returns its user. An unknown account sets UnknownAccount on the event and
// returns the account in Outcome.Unlinked; it creates no user.
func (s *Step) Finish(ctx context.Context, flow Flow, data AuthData) (Outcome, error) {
	if !s.signed(data) {
		return Outcome{}, ErrBadHash
	}
	now := s.now().UTC()
	if !now.Before(data.authDate.Add(MaxAge)) || data.authDate.After(now.Add(MaxClockSkew)) {
		return Outcome{}, ErrStale
	}
	if err := s.proofs.Cleanup(ctx, now); err != nil {
		return Outcome{}, err
	}
	// A row lives until the data is stale, so a replay always meets either the row or ErrStale.
	if err := s.proofs.Use(ctx, data.proof(), data.authDate.Add(MaxAge)); err != nil {
		return Outcome{}, err
	}
	account := data.Account()
	identity, err := s.identities.FindExternalIdentity(ctx, account)
	known := err == nil
	if err != nil && !errors.Is(err, users.ErrNotFound) {
		return Outcome{}, err
	}
	event := loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorTelegram, UnknownAccount: !known}
	if err := flow.Apply(ctx, event); err != nil {
		return Outcome{}, fmt.Errorf("telegramstep: apply %s: %w", event.Kind, err)
	}
	if !known {
		return Outcome{Unlinked: account}, nil
	}
	return Outcome{UserID: identity.UserID}, nil
}

// signed reports whether the hash of data is the HMAC of its check string.
func (s *Step) signed(data AuthData) bool {
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write([]byte(data.checkString()))
	return subtle.ConstantTimeCompare(mac.Sum(nil), data.hash) == 1
}
