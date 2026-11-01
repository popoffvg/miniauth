package totp

import "errors"

var (
	// ErrWrongCode means the code does not match, or it was accepted before.
	ErrWrongCode = errors.New("totp: wrong code")
	// ErrNotEnrolled means the user has no confirmed TOTP.
	ErrNotEnrolled = errors.New("totp: TOTP is not enrolled")
	// ErrEnrolled means the user already has a confirmed TOTP.
	ErrEnrolled = errors.New("totp: TOTP is already enrolled")
	// ErrNoEnrollment means no enrollment waits for a code, or it expired.
	ErrNoEnrollment = errors.New("totp: no enrollment waits for a code")
	// ErrKeyMissing means MINIAUTH_TOTP_KEY is not set, so no secret can be sealed or opened.
	ErrKeyMissing = errors.New("totp: TOTP key is not set")
	// ErrInvalidKey means the key is not 32 bytes in base64.
	ErrInvalidKey = errors.New("totp: TOTP key must be 32 bytes in base64")
	// ErrInvalidCode means the text is not a code of the expected form.
	ErrInvalidCode = errors.New("totp: code form is not valid")
	// ErrNoTransition means the enrollment policy refuses the event in the current stage.
	ErrNoTransition = errors.New("totp: no transition")
)
