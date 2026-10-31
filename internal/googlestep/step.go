package googlestep

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
	logger       *slog.Logger
	provider     atomic.Pointer[oidc.Provider]
	availability *sfsm.SFSM[Availability, discoveryEvent]
}

// NewStep returns a step in AvailabilityUnknown. Run Watch to discover the provider.
// A nil logger discards the log.
func NewStep(config Config, identities IdentityStore, challenges loginflow.ChallengeStore, logger *slog.Logger) (*Step, error) {
	if config.Issuer == "" || config.ClientID == (ClientID{}) || config.ClientSecret.Empty() || config.RedirectURL == "" {
		return nil, ErrConfig
	}
	if identities == nil || challenges == nil {
		return nil, errors.New("googlestep: store is missing")
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
		logger:     logger,
	}
	step.availability = sfsm.NewSFSM(AvailabilityUnknown, nextAvailability, &sfsm.SFSMOptions[Availability, discoveryEvent]{
		AfterStateChanged: func(from, to Availability, _ discoveryEvent) {
			logger.Info("googlestep: availability", "from", from, "to", to)
		},
	})
	return step, nil
}

// Begin stores the challenge of flowID and returns the Google URL and the verifier for the browser cookie.
func (s *Step) Begin(ctx context.Context, flowID loginflow.FlowID) (AuthURL, Verifier, error) {
	provider := s.provider.Load()
	if provider == nil || !s.Available() {
		return "", Verifier{}, ErrUnavailable
	}
	state, nonce, verifier, stored := newChallenge()
	if err := s.challenges.SaveChallenge(ctx, flowID, stored.encode()); err != nil {
		return "", Verifier{}, err
	}
	authURL := s.oauth(provider).AuthCodeURL(
		string(state),
		oidc.Nonce(string(nonce)),
		oauth2.S256ChallengeOption(verifier.value),
	)
	return AuthURL(authURL), verifier, nil
}

// Finish checks the callback of flowID and sends EventStepPassed with FactorGoogle to flow.
// The challenge is taken first, so a second callback for the same redirect fails.
// A known account returns its user. An unknown account sets UnknownAccount on the event and
// returns the account in Outcome.Unlinked; it creates no user.
func (s *Step) Finish(ctx context.Context, flow Flow, flowID loginflow.FlowID, verifier Verifier, state State, code Code) (Outcome, error) {
	raw, err := s.challenges.TakeChallenge(ctx, flowID)
	if errors.Is(err, loginflow.ErrChallengeNotFound) {
		return Outcome{}, ErrBadCallback
	}
	if err != nil {
		return Outcome{}, err
	}
	stored, err := decodeChallenge(raw)
	if err != nil {
		return Outcome{}, err
	}
	if !stored.matches(state, verifier) || code == "" {
		return Outcome{}, ErrBadCallback
	}
	provider := s.provider.Load()
	if provider == nil {
		return Outcome{}, ErrUnavailable
	}
	subject, err := s.subject(ctx, provider, stored, verifier, code)
	if err != nil {
		return Outcome{}, err
	}
	account := users.ExternalAccount{Kind: users.KindGoogle, Subject: subject}
	identity, err := s.identities.FindExternalIdentity(ctx, account)
	known := err == nil
	if err != nil && !errors.Is(err, users.ErrNotFound) {
		return Outcome{}, err
	}
	event := loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorGoogle, UnknownAccount: true}
	if known {
		if event, err = loginflow.Passed(ctx, s.config.SecondFactors, loginflow.FactorGoogle, identity.UserID); err != nil {
			return Outcome{}, err
		}
	}
	if err := flow.Apply(ctx, event); err != nil {
		return Outcome{}, fmt.Errorf("googlestep: apply %s: %w", event.Kind, err)
	}
	if !known {
		return Outcome{Unlinked: account}, nil
	}
	return Outcome{UserID: identity.UserID}, nil
}

// subject exchanges the code and returns the `sub` of a valid ID token.
// The exchange and verify errors are not wrapped: they can echo the token endpoint reply.
func (s *Step) subject(ctx context.Context, provider *oidc.Provider, stored challenge, verifier Verifier, code Code) (users.Subject, error) {
	exchangeCtx, cancel := context.WithTimeout(oidc.ClientContext(ctx, s.client), discoveryTimeout)
	defer cancel()
	token, err := s.oauth(provider).Exchange(exchangeCtx, string(code), oauth2.VerifierOption(verifier.value))
	if err != nil {
		s.logger.WarnContext(ctx, "googlestep: code exchange failed")
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
