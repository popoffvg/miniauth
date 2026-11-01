package groupadmin

import (
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
)

// Group is one group as the admin list shows it.
type Group struct {
	Name      groups.Name
	BuiltIn   bool
	Members   int
	Resources []GroupResource
	CreatedAt time.Time
}

// GroupResource is one resource of a group. Managed means the grant comes from the resources file.
type GroupResource struct {
	Name    access.ResourceName
	Managed bool
}

// Managed reports whether the resources file gives the group a resource.
func (g Group) Managed() bool {
	for _, resource := range g.Resources {
		if resource.Managed {
			return true
		}
	}
	return false
}
