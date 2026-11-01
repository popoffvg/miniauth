package access

import "github.com/popoffvg/miniauth/internal/groups"

// PredefinedResource is one entry of the resources file: a resource and the groups that reach it.
type PredefinedResource struct {
	Name   ResourceName
	URL    ResourceURL
	Groups []groups.Name
}
