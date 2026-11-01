package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// grantFilter is the status filter of the grant table. Empty shows every grant.
type grantFilter string

const (
	grantFilterActive  grantFilter = "active"
	grantFilterExpired grantFilter = "expired"
)

var grantChips = []filterChip{
	{Value: "", Label: "All"},
	{Value: string(grantFilterActive), Label: "Active"},
	{Value: string(grantFilterExpired), Label: "Expired"},
}

// accessPageView is the data of the access page. Resources and Grants are the rows that pass the search
// and the filter. Choices is every resource, for the grant form.
type accessPageView struct {
	Shell          shellView
	Message        pageMessage
	Notice         pageMessage
	Query          string
	Filter         grantFilter
	Resources      []accessResourceView
	Grants         []accessGrantView
	Choices        []access.Resource
	TotalResources int
	TotalGrants    int
}

// accessResourceView is one resource row. A Managed row comes from the resources file and offers no delete.
type accessResourceView struct {
	Name    access.ResourceName
	URL     access.ResourceURL
	Grants  int
	Managed bool
}

// accessGrantView names exactly one of User and Group. A zero ExpiresAt never expires.
// A Managed grant comes from the resources file and offers no revoke.
type accessGrantView struct {
	ID        access.GrantID
	Resource  access.ResourceName
	User      users.Login
	Group     groups.Name
	ExpiresAt time.Time
	Expired   bool
	Managed   bool
}

func newAccessPageView(r *http.Request, resources []access.Resource, entries []access.GrantEntry, now time.Time) accessPageView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := grantFilter(r.URL.Query().Get("status"))
	if filter != grantFilterActive && filter != grantFilterExpired {
		filter = ""
	}
	view := accessPageView{Query: query, Filter: filter, Choices: resources, TotalResources: len(resources), TotalGrants: len(entries)}
	for _, resource := range resources {
		row := accessResourceView{Name: resource.Name, URL: resource.URL, Managed: resource.Managed}
		for _, entry := range entries {
			if entry.Grant.Resource == resource.Name {
				row.Grants++
			}
		}
		if matchesQuery(query, resource.Name.String(), resource.URL.String()) {
			view.Resources = append(view.Resources, row)
		}
	}
	for _, entry := range entries {
		grant := accessGrantView{ID: entry.Grant.ID, Resource: entry.Grant.Resource, User: entry.UserLogin, Expired: !entry.Grant.Expiry.ActiveAt(now), Managed: entry.Grant.Managed}
		grant.Group, _ = entry.Grant.Subject.Group()
		grant.ExpiresAt, _ = entry.Grant.Expiry.Time()
		if filter == grantFilterActive && grant.Expired || filter == grantFilterExpired && !grant.Expired {
			continue
		}
		if !matchesQuery(query, grant.Resource.String(), entry.URL.String(), grant.User.String(), grant.Group.String()) {
			continue
		}
		view.Grants = append(view.Grants, grant)
	}
	return view
}
