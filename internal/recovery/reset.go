package recovery

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// LinkLifetime is how long a reset link stays open.
const LinkLifetime = 30 * time.Minute

// Reset is one open reset link. The token is not a field: the mail carries it, and the database stores Hash.
type Reset struct {
	Hash      TokenHash
	UserID    users.ID
	CreatedAt time.Time
	ExpiresAt time.Time
}
