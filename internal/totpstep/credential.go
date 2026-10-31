package totpstep

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// EnrollmentTTL is how long an enrollment waits for its first code.
const EnrollmentTTL = 15 * time.Minute

// Credential is the stored TOTP of one user.
// A zero ConfirmedAt is an enrollment that waits for its first code.
type Credential struct {
	UserID      users.ID
	Sealed      SealedSecret
	LastStep    TimeStep
	CreatedAt   time.Time
	ConfirmedAt time.Time
}

// Confirmed reports whether the first code was accepted.
func (c Credential) Confirmed() bool {
	return !c.ConfirmedAt.IsZero()
}

// Enrollment is what the enrollment page shows once: the secret and its QR code text.
type Enrollment struct {
	Secret Secret
	URI    KeyURI
}
