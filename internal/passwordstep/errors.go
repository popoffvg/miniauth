package passwordstep

import (
	"errors"
	"time"
)

var (
	// ErrWrongCredentials means the login is unknown or the password does not match.
	// The two cases share one error, so a reply cannot show which logins exist.
	ErrWrongCredentials = errors.New("passwordstep: wrong login or password")
	// ErrTooSoon means the backoff for the login or the client IP has not ended.
	ErrTooSoon = errors.New("passwordstep: too many failed tries")
	// ErrInvalidClientIP means the client address is not a valid IP address.
	ErrInvalidClientIP = errors.New("passwordstep: client IP is not valid")
)

// TooSoonError tells when the next try is accepted. It matches ErrTooSoon.
type TooSoonError struct {
	RetryAt time.Time
}

func (e *TooSoonError) Error() string {
	return ErrTooSoon.Error()
}

// Unwrap returns ErrTooSoon.
func (e *TooSoonError) Unwrap() error {
	return ErrTooSoon
}
