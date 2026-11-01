package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/views"
)

func newAccessPageView(r *http.Request, resources []access.Resource, entries []access.GrantEntry, now time.Time) views.AccessView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := views.GrantFilter(r.URL.Query().Get("status"))
	if filter != views.GrantFilterActive && filter != views.GrantFilterExpired {
		filter = ""
	}
	view := views.AccessView{Query: query, Filter: filter, Choices: resources, TotalResources: len(resources), TotalGrants: len(entries)}
	for _, resource := range resources {
		row := views.AccessResource{Name: resource.Name, URL: resource.URL, Managed: resource.Managed}
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
		grant := views.AccessGrant{ID: entry.Grant.ID, Resource: entry.Grant.Resource, User: entry.UserLogin, Expired: !entry.Grant.Expiry.ActiveAt(now), Managed: entry.Grant.Managed}
		grant.Group, _ = entry.Grant.Subject.Group()
		grant.ExpiresAt, _ = entry.Grant.Expiry.Time()
		if filter == views.GrantFilterActive && grant.Expired || filter == views.GrantFilterExpired && !grant.Expired {
			continue
		}
		if !matchesQuery(query, grant.Resource.String(), entry.URL.String(), grant.User.String(), grant.Group.String()) {
			continue
		}
		view.Grants = append(view.Grants, grant)
	}
	return view
}
