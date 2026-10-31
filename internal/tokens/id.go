package tokens

import (
	"fmt"
	"uuid"
)

// ID identifies one token. It is not a secret.
type ID uuid.UUID

// NewID returns a random UUID.
func NewID() ID {
	return ID(uuid.New())
}

// IDFromBytes returns the id for the 16 UUID bytes.
func IDFromBytes(b [16]byte) ID {
	return ID(b)
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
		return nil, fmt.Errorf("tokens: id: %w", err)
	}
	return text, nil
}

// UnmarshalText reads the UUID text form.
func (id *ID) UnmarshalText(text []byte) error {
	parsed, err := uuid.Parse(string(text))
	if err != nil {
		return fmt.Errorf("tokens: id: %w", err)
	}
	*id = ID(parsed)
	return nil
}

// ParseID reads the text form. A malformed id is ErrNotFound: no token has it.
func ParseID(raw string) (ID, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return ID{}, ErrNotFound
	}
	return ID(parsed), nil
}
