package sessions

import (
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// Lifetime is how long a session stays valid after it is issued or extended.
	Lifetime = 30 * 24 * time.Hour
	// ExtendEvery is the shortest time between writes of expires_at.
	ExtendEvery = time.Hour
)

// Session is one browser session.
// The id is not a field. The caller holds the id, and the database stores only its hash.
// DeviceID is zero for a session that was not started on a device.
type Session struct {
	UserID    users.ID
	Factors   loginflow.Factors
	AuthAt    time.Time
	ExpiresAt time.Time
	DeviceID  devices.ID
}

// extendBefore is the latest stored expiry that this call may move.
// The stored expiry is the previous extension plus Lifetime, so this is one hour after that extension.
func extendBefore(now time.Time) time.Time {
	return now.Add(Lifetime - ExtendEvery)
}

// due reports whether expires_at may move at now.
func due(expires, now time.Time) bool {
	return !expires.After(extendBefore(now))
}
