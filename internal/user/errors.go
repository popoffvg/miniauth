package user

import "errors"

var (
	// ErrLoginTaken means a user with this login is already stored.
	ErrLoginTaken = errors.New("user: login already exists")
	// ErrInvalidLogin means the login does not match the login rules.
	ErrInvalidLogin = errors.New("user: login is not valid")
	// ErrEmptyPassword means the password has no bytes.
	ErrEmptyPassword = errors.New("user: password is empty")
	// ErrPasswordTooLong means the password is longer than MaxPasswordBytes.
	ErrPasswordTooLong = errors.New("user: password is too long")
)
