package sessions

import "errors"

var (
	// ErrNotFound means the session is missing, expired, or the id does not match.
	ErrNotFound = errors.New("sessions: session is not found")
	// ErrUnknownUser means the user id is empty or not stored.
	ErrUnknownUser = errors.New("sessions: user is not known")
	// ErrDomain means the cookie domain is not a domain name.
	ErrDomain = errors.New("sessions: cookie domain is not valid")
	// ErrNoDeviceStore means the repository does not store devices.
	ErrNoDeviceStore = errors.New("sessions: repository does not store devices")
)
