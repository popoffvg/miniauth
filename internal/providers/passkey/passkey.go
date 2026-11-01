package passkey

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// CredentialID is the id the authenticator chose for the credential. It is not a secret.
type CredentialID []byte

// PublicKey is the COSE public key of the credential.
type PublicKey []byte

// SignCount is the signature counter of the authenticator. Zero means the authenticator has no counter.
type SignCount uint32

// Transport is a hint how the browser reaches the authenticator, such as "usb" or "internal".
type Transport string

// AAGUID names the authenticator model. It is all zero for attestation "none".
type AAGUID [16]byte

// Passkey is one stored credential of a user.
// BackupEligible is the BE flag of the registration. A login MUST send the same flag.
// A zero LastUsedAt means the passkey was never used.
type Passkey struct {
	ID             ID
	UserID         users.ID
	CredentialID   CredentialID
	PublicKey      PublicKey
	SignCount      SignCount
	Transports     []Transport
	AAGUID         AAGUID
	BackupEligible bool
	Name           Name
	CreatedAt      time.Time
	LastUsedAt     time.Time
}
