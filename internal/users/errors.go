package users

import "errors"

var (
	// ErrNotFound means no user has this id.
	ErrNotFound = errors.New("users: user is not found")
	// ErrLoginTaken means a user with this login is already stored.
	ErrLoginTaken = errors.New("users: login already exists")
	// ErrInvalidLogin means the login does not match the login rules.
	ErrInvalidLogin = errors.New("users: login is not valid")
	// ErrEmptyPassword means the password has no bytes.
	ErrEmptyPassword = errors.New("users: password is empty")
	// ErrPasswordTooLong means the password is longer than MaxPasswordBytes.
	ErrPasswordTooLong = errors.New("users: password is too long")
)
