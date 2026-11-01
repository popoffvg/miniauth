package groupadmin

import "errors"

var (
	// ErrManagedGroup is what Delete returns for a group that the resources file names.
	ErrManagedGroup = errors.New("groupadmin: the resources file names the group")
	// ErrNotGranted is what RemoveResource returns when the group has no grant of the resource.
	ErrNotGranted = errors.New("groupadmin: the group does not have the resource")
)
