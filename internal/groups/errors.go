package groups

import "errors"

var (
	// ErrName is what ParseName returns for a refused name.
	ErrName = errors.New("groups: name is not valid")
	// ErrDuplicate is what Add returns for a pair that is already stored.
	ErrDuplicate = errors.New("groups: membership already exists")
	// ErrUnknownUser is what Add returns when the user is not stored.
	ErrUnknownUser = errors.New("groups: user is not known")
)
