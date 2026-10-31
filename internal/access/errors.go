package access

import "errors"

var (
	// ErrResourceName is what ParseResourceName returns for a refused name.
	ErrResourceName = errors.New("access: resource name is not valid")
	// ErrHost is what ParseHost returns for a refused host.
	ErrHost = errors.New("access: host is not valid")
	// ErrPathPrefix is what ParsePathPrefix returns for a refused prefix.
	ErrPathPrefix = errors.New("access: path prefix is not valid")
	// ErrRequestURL is what ParseRequestURL returns for a refused URL.
	ErrRequestURL = errors.New("access: request URL is not valid")
	// ErrSubject means a grant names no user and no group.
	ErrSubject = errors.New("access: grant subject is not valid")
	// ErrExpiry means the expiry of a new grant is not in the future.
	ErrExpiry = errors.New("access: grant expiry is not in the future")
	// ErrNoResource means no resource matches the URL.
	ErrNoResource = errors.New("access: no resource matches the URL")
	// ErrNoGrant means the user and the user's groups have no active grant for the resource.
	ErrNoGrant = errors.New("access: no active grant for the resource")
	// ErrDuplicateResource means the name or the URL of the resource is already stored.
	ErrDuplicateResource = errors.New("access: resource already exists")
	// ErrResourceNotFound means the resource is not stored.
	ErrResourceNotFound = errors.New("access: resource is not found")
	// ErrDuplicateGrant means the subject already has a grant for the resource.
	ErrDuplicateGrant = errors.New("access: grant already exists")
	// ErrGrantNotFound means the grant is not stored.
	ErrGrantNotFound = errors.New("access: grant is not found")
	// ErrUnknownUser means the user of a grant is not stored.
	ErrUnknownUser = errors.New("access: user is not known")
)
