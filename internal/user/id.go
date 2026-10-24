package user

import (
	"fmt"
	"uuid"
)

// UserID identifies one user. It is not a secret.
//
//nolint:revive // UserID is the domain name. ID would collide with IdentityID in this package.
type UserID uuid.UUID

// IdentityID identifies one identity. It is not a secret.
type IdentityID uuid.UUID

// NewUserID returns a random UUID.
func NewUserID() UserID {
	return UserID(uuid.New())
}

// NewIdentityID returns a random UUID.
func NewIdentityID() IdentityID {
	return IdentityID(uuid.New())
}

// UserIDFromBytes returns the id for the 16 UUID bytes.
//
//nolint:revive // UserID is the domain name. IDFromBytes would not say which id.
func UserIDFromBytes(b [16]byte) UserID {
	return UserID(b)
}

// IdentityIDFromBytes returns the id for the 16 UUID bytes.
func IdentityIDFromBytes(b [16]byte) IdentityID {
	return IdentityID(b)
}

func (id UserID) String() string {
	return uuid.UUID(id).String()
}

// Bytes returns the 16-byte UUID form.
func (id UserID) Bytes() [16]byte {
	return uuid.UUID(id)
}

// MarshalText encodes the UUID text form.
func (id UserID) MarshalText() ([]byte, error) {
	text, err := uuid.UUID(id).MarshalText()
	if err != nil {
		return nil, fmt.Errorf("user: user id: %w", err)
	}
	return text, nil
}

// UnmarshalText reads the UUID text form.
func (id *UserID) UnmarshalText(text []byte) error {
	parsed, err := uuid.Parse(string(text))
	if err != nil {
		return fmt.Errorf("user: user id: %w", err)
	}
	*id = UserID(parsed)
	return nil
}

func (id IdentityID) String() string {
	return uuid.UUID(id).String()
}

// Bytes returns the 16-byte UUID form.
func (id IdentityID) Bytes() [16]byte {
	return uuid.UUID(id)
}

// MarshalText encodes the UUID text form.
func (id IdentityID) MarshalText() ([]byte, error) {
	text, err := uuid.UUID(id).MarshalText()
	if err != nil {
		return nil, fmt.Errorf("user: identity id: %w", err)
	}
	return text, nil
}

// UnmarshalText reads the UUID text form.
func (id *IdentityID) UnmarshalText(text []byte) error {
	parsed, err := uuid.Parse(string(text))
	if err != nil {
		return fmt.Errorf("user: identity id: %w", err)
	}
	*id = IdentityID(parsed)
	return nil
}
