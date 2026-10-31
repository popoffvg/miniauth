package identitylink

import "errors"

var (
	// ErrNotFound means the browser has no live pending link: it is missing, expired, or already used.
	ErrNotFound = errors.New("identitylink: pending link not found")
	// ErrAccountTaken means the outside account is linked to another user,
	// or the user already has an identity of this kind.
	ErrAccountTaken = errors.New("identitylink: account is already linked")
)
