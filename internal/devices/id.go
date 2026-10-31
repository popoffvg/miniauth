package devices

import "uuid"

// ID identifies one device in a URL. It is not a secret and not the cookie token.
type ID uuid.UUID

// NewID returns a random UUID.
func NewID() ID {
	return ID(uuid.New())
}

// IDFromBytes returns the id for the 16 UUID bytes.
func IDFromBytes(b [16]byte) ID {
	return ID(b)
}

// ParseID reads the UUID text form.
// Any other text is ErrNotFound, so a malformed id and a foreign id look the same.
func ParseID(text string) (ID, error) {
	parsed, err := uuid.Parse(text)
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
