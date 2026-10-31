package devices

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// CookieLifetime is how long the device cookie lives after the last login on it.
const CookieLifetime = 2 * 365 * 24 * time.Hour

// Device is one browser of one user.
// The same browser used by two users is two devices.
type Device struct {
	ID        ID
	UserID    users.ID
	Name      Name
	FirstSeen time.Time
	LastSeen  time.Time
}

// Visit is a login on a device.
// NewID is the id of the row when the token is not stored yet for the user.
type Visit struct {
	NewID     ID
	TokenHash TokenHash
	Name      Name
	At        time.Time
}
