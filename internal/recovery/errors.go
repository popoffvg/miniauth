package recovery

import "errors"

var (
	// ErrInvalidToken means the reset token is malformed, unknown, used, expired, or belongs to a disabled user.
	// The cases share one error, so a reply cannot show which tokens exist.
	ErrInvalidToken = errors.New("recovery: reset link is not valid")
	// ErrQueueFull means the mail queue has no free slot. The mail is not sent.
	ErrQueueFull = errors.New("recovery: mail queue is full")
)
