package telegram

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
// Release deletes hash. Finish calls it when the step fails after Use, so a retry is not a replay.
// Cleanup deletes the rows that expired at or before now.
type ProofStore interface {
	Use(ctx context.Context, hash ProofHash, expiresAt time.Time) error
	Release(ctx context.Context, hash ProofHash) error
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
	steps      loginflow.StepStore
	// secondFactors is nil when no user has a second factor.
	secondFactors loginflow.SecondFactors
	now           func() time.Time
}

// NewStep returns a step for the bot in config.
func NewStep(config Config, identities IdentityStore, proofs ProofStore, steps loginflow.StepStore) (*Step, error) {
	if config.BotName == (BotName{}) || config.BotToken.Empty() {
		return nil, ErrConfig
	}
	if identities == nil || proofs == nil || steps == nil {
		return nil, errors.New("telegram: store is missing")
	}
	return &Step{
		botName:       config.BotName,
		key:           sha256.Sum256([]byte(config.BotToken.value)),
		identities:    identities,
		proofs:        proofs,
		steps:         steps,
		secondFactors: config.SecondFactors,
		now:           time.Now,
	}, nil
}

// BotName is the bot that the widget shows.
func (s *Step) BotName() BotName {
	return s.botName
}

// Show starts the step of flowID in StepWidgetShown. Call it each time a page shows the widget.
func (s *Step) Show(ctx context.Context, flowID loginflow.FlowID) error {
	return s.steps.BeginStep(ctx, flowID, StepWidgetShown.stored())
}

// Finish checks data, moves the step of flowID through stepPolicy, and sends the flow event of the final step state.
// A step that is not in StepWidgetShown refuses the data with ErrNoTransition.
// The hash and the age are checked first. Then the proof of data is stored, so the same data passes once.
// A failure after that releases the proof, so a retry of the same data is not a replay.
// A known account returns its user. An unknown account sets UnknownAccount on the event and
// returns the account in Outcome.Unlinked; it creates no user.
// Bad data sends EventStepFailed and returns its own error, also when the flow refuses the event.
func (s *Step) Finish(ctx context.Context, flow Flow, flowID loginflow.FlowID, data AuthData) (Outcome, error) {
	stored, err := s.steps.LoadStep(ctx, flowID)
	if err != nil {
		return Outcome{}, err
	}
	found, dataErr := s.check(ctx, data)
	if found.event == "" {
		return Outcome{}, dataErr
	}
	outcome, err := s.end(ctx, flow, flowID, StepState(stored), found, dataErr)
	if err != nil && found.event != EventDataBad {
		return Outcome{}, s.release(ctx, data, err)
	}
	return outcome, err
}

// dataCheck is what check found. An empty event means the check itself failed, not the data.
type dataCheck struct {
	event    StepEvent
	account  users.ExternalAccount
	identity users.Identity
}

// check runs every check of data, stores its proof, and names the step event.
// EventDataBad comes with the error that Finish returns.
func (s *Step) check(ctx context.Context, data AuthData) (dataCheck, error) {
	bad := dataCheck{event: EventDataBad}
	if !s.signed(data) {
		return bad, ErrBadHash
	}
	now := s.now().UTC()
	if !now.Before(data.authDate.Add(MaxAge)) || data.authDate.After(now.Add(MaxClockSkew)) {
		return bad, ErrStale
	}
	if err := s.proofs.Cleanup(ctx, now); err != nil {
		return dataCheck{}, err
	}
	// A row lives until the data is stale, so a replay always meets either the row or ErrStale.
	if err := s.proofs.Use(ctx, data.proof(), data.authDate.Add(MaxAge)); err != nil {
		if dataBad(err) {
			return bad, err
		}
		return dataCheck{}, err
	}
	account := data.Account()
	identity, err := s.identities.FindExternalIdentity(ctx, account)
	if errors.Is(err, users.ErrNotFound) {
		return dataCheck{event: EventDataUnknown, account: account}, nil
	}
	if err != nil {
		return dataCheck{}, s.release(ctx, data, err)
	}
	return dataCheck{event: EventDataKnown, account: account, identity: identity}, nil
}

// end moves the step from the stored state and applies the flow event of the final state.
func (s *Step) end(ctx context.Context, flow Flow, flowID loginflow.FlowID, from StepState, found dataCheck, dataErr error) (Outcome, error) {
	to, err := NextStep(from, found.event)
	if err != nil {
		return Outcome{}, errors.Join(err, dataErr)
	}
	if err = s.steps.MoveStep(ctx, flowID, from.stored(), to.stored()); err != nil {
		if errors.Is(err, loginflow.ErrStepMoved) {
			err = fmt.Errorf("%w: %w", ErrNoTransition, err)
		}
		return Outcome{}, errors.Join(err, dataErr)
	}
	event, err := s.flowEvent(ctx, to, found.identity.UserID)
	if err != nil {
		return Outcome{}, errors.Join(dataErr, err)
	}
	if err = flow.Apply(ctx, event); err != nil {
		return Outcome{}, errors.Join(dataErr, fmt.Errorf("telegram: apply %s: %w", event.Kind, err))
	}
	switch {
	case dataErr != nil:
		return Outcome{}, dataErr
	case to == StepUnknownAccount:
		return Outcome{Unlinked: found.account}, nil
	default:
		return Outcome{UserID: found.identity.UserID}, nil
	}
}

// flowEvent is the login flow event of the final step state. StepPassed reads NeedsSecond from the store.
func (s *Step) flowEvent(ctx context.Context, state StepState, userID users.ID) (loginflow.Event, error) {
	switch state {
	case StepPassed:
		return loginflow.Passed(ctx, s.secondFactors, loginflow.FactorTelegram, userID)
	case StepUnknownAccount:
		return loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorTelegram, UnknownAccount: true}, nil
	default:
		return loginflow.Event{Kind: loginflow.EventStepFailed, Factor: loginflow.FactorTelegram}, nil
	}
}

// release deletes the stored proof of data after err, so a retry of the same data is not a replay.
func (s *Step) release(ctx context.Context, data AuthData, err error) error {
	if releaseErr := s.proofs.Release(context.WithoutCancel(ctx), data.proof()); releaseErr != nil {
		return errors.Join(err, releaseErr)
	}
	return err
}

// signed reports whether the hash of data is the HMAC of its check string.
func (s *Step) signed(data AuthData) bool {
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write([]byte(data.checkString()))
	return subtle.ConstantTimeCompare(mac.Sum(nil), data.hash) == 1
}
