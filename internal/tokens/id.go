package tokens

import "uuid"

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
