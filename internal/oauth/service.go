package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// AccessTokenLifetime is how long an access token from the token endpoint works.
const AccessTokenLifetime = time.Hour

// Store keeps clients, consents, codes, and refresh tokens.
// FindClient and DeleteClient MUST return ErrClientNotFound for a missing id.
// DeleteClient also deletes the access tokens of its consents.
// SaveConsent returns the active consent for the same user, client, and resource when one is stored.
// RevokeConsent MUST return ErrConsentNotFound when the user has no active consent with the id.
// RevokeConsent and EndConsent delete the access tokens and the refresh tokens of the consent.
type Store interface {
	CreateClient(ctx context.Context, client Client) error
	FindClient(ctx context.Context, id ClientID) (Client, error)
	ListClients(ctx context.Context) ([]Client, error)
	DeleteClient(ctx context.Context, id ClientID) error
	SaveConsent(ctx context.Context, consent Consent) (Consent, error)
	ListConsents(ctx context.Context, userID users.ID) ([]ConsentEntry, error)
	RevokeConsent(ctx context.Context, userID users.ID, id ConsentID, at time.Time) error
	EndConsent(ctx context.Context, id ConsentID, at time.Time) error
	CreateCode(ctx context.Context, code AuthorizationCode) error
	InTransaction(ctx context.Context, fn func(Transaction) error) error
}

// Transaction is one token request.
// ClaimCode and ClaimRefresh set used_at once. A hash that is not stored is ErrInvalidGrant.
// A hash used before is ErrCodeReused or ErrRefreshReused, returned with the stored row and its consent.
type Transaction interface {
	ClaimCode(ctx context.Context, hash CodeHash, at time.Time) (AuthorizationCode, Consent, error)
	ClaimRefresh(ctx context.Context, hash RefreshHash, at time.Time) (RefreshToken, Consent, error)
	CreateAccessToken(ctx context.Context, token tokens.Token, hash tokens.Hash, consent ConsentID) error
	CreateRefresh(ctx context.Context, refresh RefreshToken) error
}

// Accounts finds the owner of a consent. Find MUST return users.ErrNotFound for a missing user.
type Accounts interface {
	Find(ctx context.Context, id users.ID) (users.User, error)
}

// IssuedTokens is the reply of the token endpoint. Access and Refresh are clear: they MUST NOT reach a log.
type IssuedTokens struct {
	Access          tokens.Secret
	AccessExpiresAt time.Time
	Refresh         RefreshSecret
	Resource        tokens.Scope
}

// Service registers clients, records consents, and exchanges codes and refresh tokens.
type Service struct {
	store    Store
	accounts Accounts
	now      func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
func NewService(store Store, accounts Accounts) *Service {
	return &Service{store: store, accounts: accounts, now: time.Now}
}

// NewServiceWithClock returns a service that reads the clock from now.
func NewServiceWithClock(store Store, accounts Accounts, now func() time.Time) *Service {
	return &Service{store: store, accounts: accounts, now: now}
}

// RegisterClient stores a client with at least one redirect URI.
func (s *Service) RegisterClient(ctx context.Context, name ClientName, redirectURIs []RedirectURI) (Client, error) {
	if err := s.ready(); err != nil {
		return Client{}, err
	}
	if name.value == "" {
		return Client{}, ErrClientName
	}
	if len(redirectURIs) == 0 {
		return Client{}, ErrRedirectURI
	}
	for _, uri := range redirectURIs {
		if uri.value == "" {
			return Client{}, ErrRedirectURI
		}
	}
	client := Client{ID: NewClientID(), Name: name, RedirectURIs: redirectURIs, CreatedAt: s.clock()}
	if err := s.store.CreateClient(ctx, client); err != nil {
		return Client{}, err
	}
	return client, nil
}

// FindClient returns the client, or ErrClientNotFound.
func (s *Service) FindClient(ctx context.Context, id ClientID) (Client, error) {
	if err := s.ready(); err != nil {
		return Client{}, err
	}
	return s.store.FindClient(ctx, id)
}

// ListClients returns every client, oldest first.
func (s *Service) ListClients(ctx context.Context) ([]Client, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.store.ListClients(ctx)
}

// DeleteClient deletes the client, its consents, and every token it got. The next /auth/check refuses them.
func (s *Service) DeleteClient(ctx context.Context, id ClientID) error {
	if err := s.ready(); err != nil {
		return err
	}
	return s.store.DeleteClient(ctx, id)
}

// HasConsent reports whether the user approved the client for the resource of request before.
func (s *Service) HasConsent(ctx context.Context, userID users.ID, request AuthorizeRequest) (bool, error) {
	consents, err := s.ListConsents(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, entry := range consents {
		if entry.Consent.ClientID == request.Client.ID && entry.Consent.Resource == request.Resource {
			return true, nil
		}
	}
	return false, nil
}

// Approve records the consent of the user for request and returns a new authorization code.
// A consent stored before is kept, so an approved client gets a code with no page.
func (s *Service) Approve(ctx context.Context, userID users.ID, request AuthorizeRequest) (Code, error) {
	if err := s.ready(); err != nil {
		return Code{}, err
	}
	now := s.clock()
	consent, err := s.store.SaveConsent(ctx, Consent{
		ID:        NewConsentID(),
		UserID:    userID,
		ClientID:  request.Client.ID,
		Resource:  request.Resource,
		CreatedAt: now,
	})
	if err != nil {
		return Code{}, err
	}
	code, err := NewCode()
	if err != nil {
		return Code{}, err
	}
	err = s.store.CreateCode(ctx, AuthorizationCode{
		Hash:        code.Hash(),
		ConsentID:   consent.ID,
		RedirectURI: request.RedirectURI,
		Challenge:   request.Challenge,
		CreatedAt:   now,
		ExpiresAt:   now.Add(CodeLifetime),
	})
	if err != nil {
		return Code{}, err
	}
	return code, nil
}

// ExchangeCode spends the code and issues an access token and a refresh token.
// The client, the redirect URI, and the verifier MUST match the authorization request, else ErrInvalidGrant.
// A code spent before ends its consent: a second exchange means the code leaked.
func (s *Service) ExchangeCode(ctx context.Context, clientID ClientID, code Code, redirectURI RedirectURI, verifier Verifier) (IssuedTokens, error) {
	if err := s.ready(); err != nil {
		return IssuedTokens{}, err
	}
	client, err := s.store.FindClient(ctx, clientID)
	if err != nil {
		return IssuedTokens{}, err
	}
	now := s.clock()
	var issued IssuedTokens
	var reused Consent
	err = s.store.InTransaction(ctx, func(tx Transaction) error {
		stored, consent, claimErr := tx.ClaimCode(ctx, code.Hash(), now)
		if errors.Is(claimErr, ErrCodeReused) {
			reused = consent
			return ErrInvalidGrant
		}
		if claimErr != nil {
			return claimErr
		}
		if !stored.ExpiresAt.After(now) || consent.ClientID != clientID ||
			stored.RedirectURI.value != redirectURI.value || !stored.Challenge.Verifies(verifier) {
			return ErrInvalidGrant
		}
		var issueErr error
		issued, issueErr = s.issue(ctx, tx, client, consent, now)
		return issueErr
	})
	if reused.ID != (ConsentID{}) {
		if endErr := s.store.EndConsent(ctx, reused.ID, now); endErr != nil {
			return IssuedTokens{}, endErr
		}
	}
	if err != nil {
		return IssuedTokens{}, err
	}
	return issued, nil
}

// Refresh rotates the refresh token: it spends secret and issues a new access token and a new refresh token.
// A refresh token spent before ends its consent: a second use means the token leaked.
func (s *Service) Refresh(ctx context.Context, clientID ClientID, secret RefreshSecret) (IssuedTokens, error) {
	if err := s.ready(); err != nil {
		return IssuedTokens{}, err
	}
	client, err := s.store.FindClient(ctx, clientID)
	if err != nil {
		return IssuedTokens{}, err
	}
	now := s.clock()
	var issued IssuedTokens
	var reused Consent
	err = s.store.InTransaction(ctx, func(tx Transaction) error {
		stored, consent, claimErr := tx.ClaimRefresh(ctx, secret.Hash(), now)
		if errors.Is(claimErr, ErrRefreshReused) {
			reused = consent
			return ErrInvalidGrant
		}
		if claimErr != nil {
			return claimErr
		}
		if !stored.ExpiresAt.After(now) || consent.ClientID != clientID {
			return ErrInvalidGrant
		}
		var issueErr error
		issued, issueErr = s.issue(ctx, tx, client, consent, now)
		return issueErr
	})
	if reused.ID != (ConsentID{}) {
		if endErr := s.store.EndConsent(ctx, reused.ID, now); endErr != nil {
			return IssuedTokens{}, endErr
		}
	}
	if err != nil {
		return IssuedTokens{}, err
	}
	return issued, nil
}

// ListConsents returns the active consents of the user, oldest first.
func (s *Service) ListConsents(ctx context.Context, userID users.ID) ([]ConsentEntry, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	return s.store.ListConsents(ctx, userID)
}

// RevokeConsent ends the consent and every token issued under it. The next authorization shows the consent page.
func (s *Service) RevokeConsent(ctx context.Context, userID users.ID, id ConsentID) error {
	if err := s.ready(); err != nil {
		return err
	}
	return s.store.RevokeConsent(ctx, userID, id, s.clock())
}

// issue refuses a revoked consent and a disabled or deleted owner, then stores both tokens.
func (s *Service) issue(ctx context.Context, tx Transaction, client Client, consent Consent, now time.Time) (IssuedTokens, error) {
	if consent.Revoked() {
		return IssuedTokens{}, ErrInvalidGrant
	}
	owner, err := s.accounts.Find(ctx, consent.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && owner.Disabled() {
		return IssuedTokens{}, ErrInvalidGrant
	}
	if err != nil {
		return IssuedTokens{}, err
	}
	name, err := tokens.ParseName(client.Name.String())
	if err != nil {
		return IssuedTokens{}, fmt.Errorf("oauth: token name of client %s: %w", client.ID, err)
	}
	access, err := tokens.NewSecret()
	if err != nil {
		return IssuedTokens{}, err
	}
	expiresAt := now.Add(AccessTokenLifetime)
	token := tokens.Token{
		ID:        tokens.NewID(),
		UserID:    consent.UserID,
		Prefix:    access.Prefix(),
		Name:      name,
		Scopes:    tokens.Scopes{consent.Resource},
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	if err = tx.CreateAccessToken(ctx, token, access.Hash(), consent.ID); err != nil {
		return IssuedTokens{}, err
	}
	refresh, err := NewRefreshSecret()
	if err != nil {
		return IssuedTokens{}, err
	}
	err = tx.CreateRefresh(ctx, RefreshToken{
		Hash:      refresh.Hash(),
		ConsentID: consent.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(RefreshLifetime),
	})
	if err != nil {
		return IssuedTokens{}, err
	}
	return IssuedTokens{Access: access, AccessExpiresAt: expiresAt, Refresh: refresh, Resource: consent.Resource}, nil
}

func (s *Service) ready() error {
	if s == nil || s.store == nil || s.accounts == nil {
		return errors.New("oauth: store or accounts is missing")
	}
	return nil
}

// clock returns UTC truncated to microseconds. PostgreSQL timestamptz stores microseconds.
func (s *Service) clock() time.Time {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	return now().UTC().Truncate(time.Microsecond)
}
