package oauth

import (
	"fmt"
	"time"
	"uuid"

	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// ConsentID identifies one consent. It is not a secret.
type ConsentID uuid.UUID

// NewConsentID returns a random UUID.
func NewConsentID() ConsentID {
	return ConsentID(uuid.New())
}

// ConsentIDFromBytes returns the id for the 16 UUID bytes.
func ConsentIDFromBytes(b [16]byte) ConsentID {
	return ConsentID(b)
}

// ParseConsentID reads the text form. A malformed id is ErrConsentNotFound.
func ParseConsentID(raw string) (ConsentID, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return ConsentID{}, ErrConsentNotFound
	}
	return ConsentID(parsed), nil
}

func (id ConsentID) String() string {
	return uuid.UUID(id).String()
}

// Bytes returns the 16-byte UUID form.
func (id ConsentID) Bytes() [16]byte {
	return uuid.UUID(id)
}

// MarshalText encodes the UUID text form.
func (id ConsentID) MarshalText() ([]byte, error) {
	text, err := uuid.UUID(id).MarshalText()
	if err != nil {
		return nil, fmt.Errorf("oauth: consent id: %w", err)
	}
	return text, nil
}

// Consent is the approval of one user for one client to reach one resource.
// While it is active, the consent page is not shown again. A revoke ends its access and refresh tokens.
type Consent struct {
	ID        ConsentID
	UserID    users.ID
	ClientID  ClientID
	Resource  tokens.Scope
	CreatedAt time.Time
	RevokedAt time.Time
}

// Revoked reports whether the user or a reused secret ended the consent.
func (c Consent) Revoked() bool {
	return !c.RevokedAt.IsZero()
}

// ConsentEntry is an active consent with the name of its client, for the token page.
type ConsentEntry struct {
	Consent    Consent
	ClientName ClientName
}
