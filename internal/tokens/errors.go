package tokens

import "errors"

var (
	// ErrInvalid means the token is malformed, unknown, revoked, or expired.
	ErrInvalid = errors.New("tokens: token is not valid")
	// ErrNotFound means the user has no token with this id.
	ErrNotFound = errors.New("tokens: token is not found")
	// ErrDuplicate means a token with the same secret is already stored.
	ErrDuplicate = errors.New("tokens: token already exists")
	// ErrUnknownUser means the user id is empty or not stored.
	ErrUnknownUser = errors.New("tokens: user is not known")
	// ErrName means the token name does not match the name rules.
	ErrName = errors.New("tokens: name is not valid")
	// ErrScope means the scope is not an http or https URL prefix.
	ErrScope = errors.New("tokens: scope is not valid")
	// ErrExpiry means the expiry is not in the future.
	ErrExpiry = errors.New("tokens: expiry is not in the future")
)
