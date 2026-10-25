package users

import (
	"fmt"
	"uuid"
)

// ID identifies one user. It is not a secret.
type ID uuid.UUID

// IdentityID identifies one identity. It is not a secret.
type IdentityID uuid.UUID

// NewID returns a random UUID.
func NewID() ID {
	return ID(uuid.New())
}

// NewIdentityID returns a random UUID.
func NewIdentityID() IdentityID {
	return IdentityID(uuid.New())
}

// IDFromBytes returns the id for the 16 UUID bytes.
func IDFromBytes(b [16]byte) ID {
	return ID(b)
}

// IdentityIDFromBytes returns the id for the 16 UUID bytes.
func IdentityIDFromBytes(b [16]byte) IdentityID {
	return IdentityID(b)
}

func (id ID) String() string {
	return uuid.UUID(id).String()
}

// Bytes returns the 16-byte UUID form.
func (id ID) Bytes() [16]byte {
	return uuid.UUID(id)
}

// MarshalText encodes the UUID text form.
func (id ID) MarshalText() ([]byte, error) {
	text, err := uuid.UUID(id).MarshalText()
	if err != nil {
		return nil, fmt.Errorf("users: id: %w", err)
	}
	return text, nil
}

// UnmarshalText reads the UUID text form.
func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := uuid.Parse(string(text))
	if err != nil {
		return fmt.Errorf("users: id: %w", err)
	}
	*id = ID(parsed)
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
		return nil, fmt.Errorf("users: identity id: %w", err)
	}
	return text, nil
}

// UnmarshalText reads the UUID text form.
func (id *IdentityID) UnmarshalText(text []byte) error {
	parsed, err := uuid.Parse(string(text))
	if err != nil {
		return fmt.Errorf("users: identity id: %w", err)
	}
	*id = IdentityID(parsed)
	return nil
}
