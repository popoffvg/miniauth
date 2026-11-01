package passkey

import "uuid"

// ID identifies one stored passkey. It is not the credential id.
type ID uuid.UUID

// NewID returns a random UUID.
func NewID() ID {
	return ID(uuid.New())
}

// IDFromBytes returns the id for the 16 UUID bytes.
func IDFromBytes(b [16]byte) ID {
	return ID(b)
}

// ParseID reads the text form. A malformed id is ErrNotFound: no passkey has it.
func ParseID(raw string) (ID, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return ID{}, ErrNotFound
	}
	return ID(parsed), nil
}

func (id ID) String() string {
	return uuid.UUID(id).String()
}

// Bytes returns the 16-byte UUID form.
func (id ID) Bytes() [16]byte {
	return uuid.UUID(id)
}
