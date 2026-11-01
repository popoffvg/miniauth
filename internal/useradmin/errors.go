package useradmin

import "errors"

var (
	// ErrUserNotFound is what each change returns for a login that is not stored.
	ErrUserNotFound = errors.New("useradmin: user is not found")
	// ErrNotMember is what RemoveFromGroup returns when the user is not in the group.
	ErrNotMember = errors.New("useradmin: user is not in the group")
	// ErrSelfDisable is what Disable returns when the actor names itself.
	ErrSelfDisable = errors.New("useradmin: an administrator cannot disable itself")
	// ErrSelfAdmin is what RemoveFromGroup returns when the actor removes its own admin membership.
	ErrSelfAdmin = errors.New("useradmin: an administrator cannot leave the admins group")
)
