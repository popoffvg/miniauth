package access

import (
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// Grantee names the subject of a new grant the way an operator types it: a user login or a group name.
// Exactly one field MUST be set.
type Grantee struct {
	User  users.Login
	Group groups.Name
}

// Valid reports a grantee with exactly one of a user and a group.
func (g Grantee) Valid() bool {
	return (g.User != users.Login{}) != (g.Group != groups.Name{})
}

// GrantFilter selects grants. A zero field matches every grant.
// User matches the grants to that user only, not the grants to the user's groups.
type GrantFilter struct {
	User     users.Login
	Resource ResourceName
}

// GrantEntry is a grant with the URL of its resource and the login of its user, so a list shows who can open each resource.
// UserLogin is zero for a group grant.
type GrantEntry struct {
	Grant     Grant
	URL       ResourceURL
	UserLogin users.Login
}
