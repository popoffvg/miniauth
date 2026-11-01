package groups

import "errors"

var (
	// ErrName is what ParseName returns for a refused name.
	ErrName = errors.New("groups: name is not valid")
	// ErrDuplicate is what Add returns for a pair that is already stored.
	ErrDuplicate = errors.New("groups: membership already exists")
	// ErrUnknownUser is what Add returns when the user is not stored.
	ErrUnknownUser = errors.New("groups: user is not known")
	// ErrGroupNotFound means no group has the name.
	ErrGroupNotFound = errors.New("groups: group is not found")
	// ErrDuplicateGroup means a group with the name already exists.
	ErrDuplicateGroup = errors.New("groups: group already exists")
	// ErrBuiltIn means the change would delete a built-in group.
	ErrBuiltIn = errors.New("groups: a built-in group cannot be deleted")
)
