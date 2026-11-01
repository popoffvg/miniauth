package oauth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// AccessTokenLifetime is how long an access token from the token endpoint works.
const AccessTokenLifetime = time.Hour

// Store keeps clients, consents, and codes. Refresh tokens and access tokens go through a Transaction.
type Store interface {
	CreateClient(ctx context.Context, client Client) error
	// FindClient MUST return ErrClientNotFound for a missing id.
	FindClient(ctx context.Context, id ClientID) (Client, error)
	ListClients(ctx context.Context) ([]Client, error)
	// DeleteClient MUST return ErrClientNotFound for a missing id. It deletes the access tokens of its consents.
	DeleteClient(ctx context.Context, id ClientID) error
	// SaveConsent returns the active consent for the same user, client, and resource when one is stored.
	SaveConsent(ctx context.Context, consent Consent) (Consent, error)
	ListConsents(ctx context.Context, userID users.ID) ([]ConsentEntry, error)
	// RevokeConsent MUST return ErrConsentNotFound when the user has no active consent with the id.
	// It deletes the access tokens and the refresh tokens of the consent.
	RevokeConsent(ctx context.Context, userID users.ID, id ConsentID, at time.Time) error
	// EndConsent deletes the access tokens and the refresh tokens of the consent.
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
	FindUser(ctx context.Context, id users.ID) (users.User, error)
}

// IssuedTokens is the reply of the token endpoint. Access and Refresh are clear: they MUST NOT reach a log.
type IssuedTokens struct {
	Access          tokens.Secret
	AccessExpiresAt time.Time
	Refresh         RefreshSecret
	Resource        tokens.Scope
}

// Service is the OAuth authorization server. Store keeps its state.
type Service struct {
	store     Store
	clockFunc func() time.Time
}

// NewService reads the clock from time.Now.
func NewService(store Store) (*Service, error) {
	return NewServiceWithClock(store, time.Now)
}

// NewServiceWithClock refuses a nil store or clock before any request.
func NewServiceWithClock(store Store, clockFunc func() time.Time) (*Service, error) {
	if store == nil || clockFunc == nil {
		return nil, errors.New("oauth: store or clock is missing")
	}
	return &Service{store: store, clockFunc: clockFunc}, nil
}

// RegisterClient stores a client with at least one redirect URI.
func (s *Service) RegisterClient(ctx context.Context, name ClientName, redirectURIs []RedirectURI) (Client, error) {
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
	return s.store.FindClient(ctx, id)
}

// ListClients returns every client, oldest first.
func (s *Service) ListClients(ctx context.Context) ([]Client, error) {
	return s.store.ListClients(ctx)
}

// DeleteClient deletes the client, its consents, and every token it got. The next /auth/check refuses them.
func (s *Service) DeleteClient(ctx context.Context, id ClientID) error {
	return s.store.DeleteClient(ctx, id)
}

// HasConsent reports whether the user approved the client for the resource of request before.
func (s *Service) HasConsent(ctx context.Context, userID users.ID, request AuthorizeRequest) (bool, error) {
	consents, err := s.ListConsents(ctx, userID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(consents, func(entry ConsentEntry) bool {
		return entry.Consent.ClientID == request.Client.ID && entry.Consent.Resource == request.Resource
	}), nil
}

// Approve records the consent of the user for request and returns a new authorization code.
// A consent stored before is kept, so an approved client gets a code with no page.
func (s *Service) Approve(ctx context.Context, userID users.ID, request AuthorizeRequest) (Code, error) {
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
// If target is not empty, it MUST match the consent resource, else ErrInvalidTarget.
// A code spent before ends its consent: a second exchange means the code leaked.
func (s *Service) ExchangeCode(ctx context.Context, clientID ClientID, code Code, redirectURI RedirectURI, verifier Verifier, target tokens.Scope) (IssuedTokens, error) {
	client, err := s.store.FindClient(ctx, clientID)
	if err != nil {
		return IssuedTokens{}, err
	}
	now := s.clock()
	var issued IssuedTokens
	var reused Consent
	err = s.store.InTransaction(ctx, func(tx Transaction) error {
		stored, consent, claimErr := tx.ClaimCode(ctx, code.Hash(), now)
		at := s.clock()
		if errors.Is(claimErr, ErrCodeReused) {
			if consent.IsGrantedTo(clientID) && stored.IsRedeemableWith(redirectURI, verifier, at) {
				reused = consent
			}
			return ErrInvalidGrant
		}
		if claimErr != nil {
			return claimErr
		}
		if !stored.IsRedeemableWith(redirectURI, verifier, at) || !consent.IsGrantedTo(clientID) {
			return ErrInvalidGrant
		}
		if target != (tokens.Scope{}) && consent.Resource != target {
			return ErrInvalidTarget
		}
		var issueErr error
		issued, issueErr = s.issue(ctx, tx, client, consent, at)
		return issueErr
	})
	return s.endReused(ctx, reused, now, issued, err)
}

// Refresh rotates the refresh token: it spends secret and issues a new access token and a new refresh token.
// If target is not empty, it MUST match the consent resource, else ErrInvalidTarget.
// A refresh token spent before ends its consent: a second use means the token leaked.
func (s *Service) Refresh(ctx context.Context, clientID ClientID, secret RefreshSecret, target tokens.Scope) (IssuedTokens, error) {
	client, err := s.store.FindClient(ctx, clientID)
	if err != nil {
		return IssuedTokens{}, err
	}
	now := s.clock()
	var issued IssuedTokens
	var reused Consent
	err = s.store.InTransaction(ctx, func(tx Transaction) error {
		stored, consent, claimErr := tx.ClaimRefresh(ctx, secret.Hash(), now)
		at := s.clock()
		if errors.Is(claimErr, ErrRefreshReused) {
			if consent.IsGrantedTo(clientID) {
				reused = consent
			}
			return ErrInvalidGrant
		}
		if claimErr != nil {
			return claimErr
		}
		if !stored.IsLiveAt(at) || !consent.IsGrantedTo(clientID) {
			return ErrInvalidGrant
		}
		if target != (tokens.Scope{}) && consent.Resource != target {
			return ErrInvalidTarget
		}
		var issueErr error
		issued, issueErr = s.issue(ctx, tx, client, consent, at)
		return issueErr
	})
	return s.endReused(ctx, reused, now, issued, err)
}

// endReused ends the consent of a reused secret after the token request rolled back.
func (s *Service) endReused(ctx context.Context, reused Consent, now time.Time, issued IssuedTokens, err error) (IssuedTokens, error) {
	if reused.ID != (ConsentID{}) {
		if endErr := s.store.EndConsent(context.WithoutCancel(ctx), reused.ID, now); endErr != nil {
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
	return s.store.ListConsents(ctx, userID)
}

// RevokeConsent ends the consent and every token issued under it. The next authorization shows the consent page.
func (s *Service) RevokeConsent(ctx context.Context, userID users.ID, id ConsentID) error {
	return s.store.RevokeConsent(ctx, userID, id, s.clock())
}

// issue refuses a disabled or deleted user, then stores both tokens.
func (s *Service) issue(ctx context.Context, tx Transaction, client Client, consent Consent, now time.Time) (IssuedTokens, error) {
	user, err := tx.FindUser(ctx, consent.UserID)
	if errors.Is(err, users.ErrNotFound) {
		return IssuedTokens{}, ErrInvalidGrant
	}
	if err != nil {
		return IssuedTokens{}, err
	}
	if user.Disabled() {
		return IssuedTokens{}, ErrInvalidGrant
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

// clock returns UTC truncated to microseconds. PostgreSQL timestamptz stores microseconds.
func (s *Service) clock() time.Time {
	return s.clockFunc().UTC().Truncate(time.Microsecond)
}
