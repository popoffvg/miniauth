package passkey

import "errors"

var (
	// ErrNotFound means the user has no passkey with this id.
	ErrNotFound = errors.New("passkey: passkey is not found")
	// ErrUnknownCredential means no active user has the credential.
	ErrUnknownCredential = errors.New("passkey: credential is not known")
	// ErrDuplicate means a passkey with the same credential id is already stored.
	ErrDuplicate = errors.New("passkey: credential is already stored")
	// ErrUserNotVerified means the authenticator did not set the UV flag.
	ErrUserNotVerified = errors.New("passkey: user is not verified")
	// ErrClonedAuthenticator means the signature counter did not move forward.
	ErrClonedAuthenticator = errors.New("passkey: signature counter did not increase")
	// ErrCeremony means the browser response does not pass the WebAuthn checks.
	ErrCeremony = errors.New("passkey: WebAuthn response is not valid")
	// ErrName means the passkey name does not match the name rules.
	ErrName = errors.New("passkey: name is not valid")
	// ErrRelyingParty means the relying party id or origin is not valid.
	ErrRelyingParty = errors.New("passkey: relying party is not valid")
)
