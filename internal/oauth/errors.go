package oauth

import "errors"

var (
	// ErrClientNotFound means no client has this id. A malformed id is also not found.
	ErrClientNotFound = errors.New("oauth: client is not found")
	// ErrClientName means the client name does not match the name rules.
	ErrClientName = errors.New("oauth: client name is not valid")
	// ErrRedirectURI means the redirect URI is not https, or not http on a loopback host.
	ErrRedirectURI = errors.New("oauth: redirect URI is not valid")
	// ErrChallenge means the PKCE challenge is missing, is not S256, or is malformed.
	ErrChallenge = errors.New("oauth: PKCE challenge is not valid")
	// ErrState means the state is longer than MaxStateLength or has a control character.
	ErrState = errors.New("oauth: state is not valid")
	// ErrInvalidGrant means the code or the refresh token is malformed, unknown, used, expired,
	// or bound to another client, redirect URI, or verifier. The token endpoint answers invalid_grant.
	ErrInvalidGrant = errors.New("oauth: grant is not valid")
	// ErrConsentNotFound means the user has no active consent with this id or for this request.
	ErrConsentNotFound = errors.New("oauth: consent is not found")
	// ErrCodeReused means the code was exchanged before. The store returns it with the consent of the code.
	ErrCodeReused = errors.New("oauth: authorization code was used before")
	// ErrRefreshReused means the refresh token was rotated before. The store returns it with the consent of the token.
	ErrRefreshReused = errors.New("oauth: refresh token was used before")
)
