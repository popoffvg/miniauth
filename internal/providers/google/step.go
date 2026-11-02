package google

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/popoffvg/sfsm"
	"golang.org/x/oauth2"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// IdentityStore finds the identity of an outside account.
// FindExternalIdentity MUST return users.ErrNotFound for an unknown account or a disabled user.
type IdentityStore interface {
	FindExternalIdentity(ctx context.Context, account users.ExternalAccount) (users.Identity, error)
}

// Flow is the login flow that receives the step result. *sfsm.PersistedSFSM from loginflow.LoginFlows.Open fits.
type Flow interface {
	Apply(ctx context.Context, event loginflow.Event) error
}

// Outcome is the result of a valid callback.
// UserID is set for a linked account. Otherwise Unlinked is the account that waits for a link.
type Outcome struct {
	UserID   users.ID
	Unlinked users.ExternalAccount
}

// Linked reports whether the account belongs to a user.
func (o Outcome) Linked() bool {
	return o.UserID != (users.ID{})
}

// AuthURL is the Google URL that the browser opens. It holds the state, the nonce, and the PKCE challenge.
type AuthURL string

// Step sends a browser to Google and checks the callback.
type Step struct {
	config       Config
	client       *http.Client
	identities   IdentityStore
	challenges   loginflow.ChallengeStore
	steps        loginflow.StepStore
	logger       *slog.Logger
	provider     atomic.Pointer[oidc.Provider]
	availability *sfsm.SFSM[Availability, discoveryEvent]
}

// NewStep returns a step in AvailabilityUnknown. Run Watch to discover the provider.
// A nil logger discards the log.
func NewStep(config Config, identities IdentityStore, challenges loginflow.ChallengeStore, steps loginflow.StepStore, logger *slog.Logger) (*Step, error) {
	if config.Issuer == "" || config.ClientID == (ClientID{}) || config.ClientSecret.Empty() || config.RedirectURL == "" {
		return nil, ErrConfig
	}
	if identities == nil || challenges == nil || steps == nil {
		return nil, errors.New("google: store is missing")
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: discoveryTimeout}
	}
	step := &Step{
		config:     config,
		client:     client,
		identities: identities,
		challenges: challenges,
		steps:      steps,
		logger:     logger,
	}
	step.availability = sfsm.NewSFSM(AvailabilityUnknown, nextAvailability, &sfsm.SFSMOptions[Availability, discoveryEvent]{
		AfterStateChanged: func(from, to Availability, _ discoveryEvent) {
			logger.Info("google: availability", "from", from, "to", to)
		},
	})
	return step, nil
}

// Begin stores the challenge of flowID, starts its step in StepStarted, and returns the Google URL and the verifier for the browser cookie.
func (s *Step) Begin(ctx context.Context, flowID loginflow.FlowID) (AuthURL, Verifier, error) {
	provider := s.provider.Load()
	if provider == nil || !s.Available() {
		return "", Verifier{}, ErrUnavailable
	}
	state, nonce, verifier, stored := newChallenge()
	if err := s.challenges.SaveChallenge(ctx, flowID, stored.encode()); err != nil {
		return "", Verifier{}, err
	}
	if err := s.steps.BeginStep(ctx, flowID, StepStarted.stored()); err != nil {
		return "", Verifier{}, err
	}
	authURL := s.oauth(provider).AuthCodeURL(
		string(state),
		oidc.Nonce(string(nonce)),
		oauth2.S256ChallengeOption(verifier.value),
	)
	return AuthURL(authURL), verifier, nil
}

// Finish checks the callback of flowID, moves its step through stepPolicy, and sends the flow event of the final step state.
// A step that is not in StepStarted refuses the callback with ErrNoTransition. The challenge is also taken, so it is used once.
// A known account returns its user. An unknown account sets UnknownAccount on the event and
// returns the account in Outcome.Unlinked; it creates no user.
// A bad callback sends EventStepFailed and returns its own error, also when the flow refuses the event.
func (s *Step) Finish(ctx context.Context, flow Flow, flowID loginflow.FlowID, verifier Verifier, state State, code Code) (Outcome, error) {
	stored, err := s.steps.LoadStep(ctx, flowID)
	if err != nil {
		return Outcome{}, err
	}
	from := StepState(stored)
	found, callbackErr := s.check(ctx, flowID, verifier, state, code)
	if found.event == "" {
		return Outcome{}, callbackErr
	}
	to, err := NextStep(from, found.event)
	if err != nil {
		return Outcome{}, errors.Join(err, callbackErr)
	}
	if err = s.steps.MoveStep(ctx, flowID, from.stored(), to.stored()); err != nil {
		if errors.Is(err, loginflow.ErrStepMoved) {
			err = fmt.Errorf("%w: %w", ErrNoTransition, err)
		}
		return Outcome{}, errors.Join(err, callbackErr)
	}
	event, err := s.flowEvent(ctx, to, found.identity.UserID)
	if err != nil {
		return Outcome{}, errors.Join(callbackErr, err)
	}
	if err = flow.Apply(ctx, event); err != nil {
		return Outcome{}, errors.Join(callbackErr, fmt.Errorf("google: apply %s: %w", event.Kind, err))
	}
	switch {
	case callbackErr != nil:
		return Outcome{}, callbackErr
	case to == StepUnknownAccount:
		return Outcome{Unlinked: found.account}, nil
	default:
		return Outcome{UserID: found.identity.UserID}, nil
	}
}

// callbackCheck is what check found. An empty event means the check itself failed, not the callback.
type callbackCheck struct {
	event    StepEvent
	account  users.ExternalAccount
	identity users.Identity
}

// check runs every check of the callback and names the step event.
// EventCallbackBad comes with the error that Finish returns.
func (s *Step) check(ctx context.Context, flowID loginflow.FlowID, verifier Verifier, state State, code Code) (callbackCheck, error) {
	bad := callbackCheck{event: EventCallbackBad}
	raw, err := s.challenges.TakeChallenge(ctx, flowID)
	if errors.Is(err, loginflow.ErrChallengeNotFound) {
		return bad, ErrBadCallback
	}
	if err != nil {
		return callbackCheck{}, err
	}
	stored, err := decodeChallenge(raw)
	if err != nil {
		return callbackCheck{}, err
	}
	if !stored.matches(state, verifier) || code == "" {
		return bad, ErrBadCallback
	}
	provider := s.provider.Load()
	if provider == nil {
		return callbackCheck{}, ErrUnavailable
	}
	subject, err := s.subject(ctx, provider, stored, verifier, code)
	if err != nil {
		return bad, err
	}
	account := users.ExternalAccount{Kind: users.KindGoogle, Subject: subject}
	identity, err := s.identities.FindExternalIdentity(ctx, account)
	if errors.Is(err, users.ErrNotFound) {
		return callbackCheck{event: EventCallbackUnknown, account: account}, nil
	}
	if err != nil {
		return callbackCheck{}, err
	}
	return callbackCheck{event: EventCallbackKnown, account: account, identity: identity}, nil
}

// flowEvent is the login flow event of the final step state. StepPassed reads NeedsSecond from the store.
func (s *Step) flowEvent(ctx context.Context, state StepState, userID users.ID) (loginflow.Event, error) {
	switch state {
	case StepPassed:
		return loginflow.Passed(ctx, s.config.SecondFactors, loginflow.FactorGoogle, userID)
	case StepUnknownAccount:
		return loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorGoogle, UnknownAccount: true}, nil
	default:
		return loginflow.Event{Kind: loginflow.EventStepFailed, Factor: loginflow.FactorGoogle}, nil
	}
}

// subject exchanges the code and returns the `sub` of a valid ID token.
// The exchange and verify errors are not wrapped: they can echo the token endpoint reply.
func (s *Step) subject(ctx context.Context, provider *oidc.Provider, stored challenge, verifier Verifier, code Code) (users.Subject, error) {
	exchangeCtx, cancel := context.WithTimeout(oidc.ClientContext(ctx, s.client), discoveryTimeout)
	defer cancel()
	token, err := s.oauth(provider).Exchange(exchangeCtx, string(code), oauth2.VerifierOption(verifier.value))
	if err != nil {
		s.logger.WarnContext(ctx, "google: code exchange failed")
		return users.Subject{}, ErrBadCallback
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return users.Subject{}, ErrBadToken
	}
	verifyCtx := oidc.ClientContext(ctx, s.client)
	idToken, err := provider.VerifierContext(verifyCtx, &oidc.Config{ClientID: s.config.ClientID.String(), Now: time.Now}).Verify(verifyCtx, rawIDToken)
	if err != nil {
		return users.Subject{}, ErrBadToken
	}
	if !stored.matchesNonce(idToken.Nonce) {
		return users.Subject{}, ErrBadToken
	}
	subject, err := users.ParseSubject(idToken.Subject)
	if err != nil {
		return users.Subject{}, ErrBadToken
	}
	return subject, nil
}

func (s *Step) oauth(provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.config.ClientID.String(),
		ClientSecret: s.config.ClientSecret.value,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  string(s.config.RedirectURL),
		Scopes:       []string{oidc.ScopeOpenID},
	}
}
