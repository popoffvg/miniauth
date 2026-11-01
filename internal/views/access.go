package views

import (
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// GrantFilter is the status filter of the grant table. Empty shows every grant.
type GrantFilter string

// The grant filters. Each is the value of the status query of GET /access.
const (
	GrantFilterActive  GrantFilter = "active"
	GrantFilterExpired GrantFilter = "expired"
)

var grantChips = []FilterChip{
	{Value: "", Label: "All"},
	{Value: string(GrantFilterActive), Label: "Active"},
	{Value: string(GrantFilterExpired), Label: "Expired"},
}

// AccessView is the data of the access page. Resources and Grants are the rows that pass the search
// and the filter. Choices is every resource, for the grant form.
type AccessView struct {
	Shell          Shell
	Message        Message
	Notice         Message
	Query          string
	Filter         GrantFilter
	Resources      []AccessResource
	Grants         []AccessGrant
	Choices        []access.Resource
	TotalResources int
	TotalGrants    int
}

// AccessResource is one resource row. A Managed row comes from the resources file and offers no delete.
type AccessResource struct {
	Name    access.ResourceName
	URL     access.ResourceURL
	Grants  int
	Managed bool
}

// AccessGrant names exactly one of User and Group. A zero ExpiresAt never expires.
// A Managed grant comes from the resources file and offers no revoke.
type AccessGrant struct {
	ID        access.GrantID
	Resource  access.ResourceName
	User      users.Login
	Group     groups.Name
	ExpiresAt time.Time
	Expired   bool
	Managed   bool
}
