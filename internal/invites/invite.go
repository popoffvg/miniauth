package invites

import (
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Lifetime is the time from the creation of an invite to its expiry.
const Lifetime = 7 * 24 * time.Hour

// Invite is one stored invite. A zero UsedAt is an unused invite.
// UserID is the account the acceptance created. It is zero until then.
type Invite struct {
	Hash      TokenHash
	Group     groups.Name
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	UserID    users.ID
}

// OpenAt reports whether the invite is unused and not expired at now.
func (i Invite) OpenAt(now time.Time) bool {
	return i.UsedAt.IsZero() && i.ExpiresAt.After(now)
}

// Acceptance is the result of one accepted invite.
type Acceptance struct {
	User  users.User
	Group groups.Name
}
