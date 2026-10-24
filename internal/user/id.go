package user

import (
	"fmt"
	"uuid"
)

// UserID identifies one user. It is not a secret.
//
//nolint:revive // UserID is the domain name. ID would collide with IdentityID in this package.
type UserID string

// IdentityID identifies one identity. It is not a secret.
type IdentityID string

// NewUserID returns a random UUID.
func NewUserID() UserID {
	return UserID(uuid.New().String())
}

// NewIdentityID returns a random UUID.
func NewIdentityID() IdentityID {
	return IdentityID(uuid.New().String())
}

// UserIDFromBytes returns the canonical form of a UUID.
//
//nolint:revive // UserID is the domain name. IDFromBytes would not say which id.
func UserIDFromBytes(b [16]byte) UserID {
	return UserID(uuid.UUID(b).String())
}

// IdentityIDFromBytes returns the canonical form of a UUID.
func IdentityIDFromBytes(b [16]byte) IdentityID {
	return IdentityID(uuid.UUID(b).String())
}

func (id UserID) String() string {
	return string(id)
}

// Bytes returns the 16-byte UUID form.
func (id UserID) Bytes() ([16]byte, error) {
	parsed, err := uuid.Parse(string(id))
	if err != nil {
		return parsed, fmt.Errorf("user: user id: %w", err)
	}
	return parsed, nil
}

func (id IdentityID) String() string {
	return string(id)
}

// Bytes returns the 16-byte UUID form.
func (id IdentityID) Bytes() ([16]byte, error) {
	parsed, err := uuid.Parse(string(id))
	if err != nil {
		return parsed, fmt.Errorf("user: identity id: %w", err)
	}
	return parsed, nil
}
