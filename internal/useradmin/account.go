package useradmin

import (
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Account is one user as the admin list shows it. A zero LastSeen means no device was ever seen.
type Account struct {
	User     users.User
	Groups   []groups.Name
	Devices  int
	LastSeen time.Time
}
