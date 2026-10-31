package tokens

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// UseEvery is the shortest time between writes of last_used_at.
const UseEvery = time.Minute

// Token is one personal access token. The clear token is not a field.
// A zero ExpiresAt never expires. A zero RevokedAt or LastUsedAt did not happen.
type Token struct {
	ID         ID
	UserID     users.ID
	Prefix     Prefix
	Name       Name
	Scopes     Scopes
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	LastUsedAt time.Time
}

// Revoked reports whether the owner revoked the token.
func (t Token) Revoked() bool {
	return !t.RevokedAt.IsZero()
}

// Expired reports whether the token expired at or before now.
func (t Token) Expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !t.ExpiresAt.After(now)
}

// usedRecently reports whether last_used_at is newer than UseEvery.
func (t Token) usedRecently(now time.Time) bool {
	return !t.LastUsedAt.IsZero() && t.LastUsedAt.After(now.Add(-UseEvery))
}
