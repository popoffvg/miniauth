package groups

import "errors"

var (
	// ErrName means the group name does not match the name rules.
	ErrName = errors.New("groups: name is not valid")
	// ErrDuplicate means the user is already in the group.
	ErrDuplicate = errors.New("groups: membership already exists")
	// ErrUnknownUser means the user id is not stored.
	ErrUnknownUser = errors.New("groups: user is not known")
)
