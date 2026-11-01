package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/views"
)

func newGroupsPageView(r *http.Request, found []groupadmin.Group, resources []access.Resource) views.GroupsView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	view := views.GroupsView{Query: query, Total: len(found)}
	for _, group := range found {
		fields := []string{group.Name.String()}
		for _, resource := range group.Resources {
			fields = append(fields, resource.Name.String())
		}
		if !matchesQuery(query, fields...) {
			continue
		}
		row := views.GroupRow{Group: group}
		for _, resource := range resources {
			has := slices.ContainsFunc(group.Resources, func(given groupadmin.GroupResource) bool { return given.Name == resource.Name })
			if !has {
				row.Addable = append(row.Addable, resource.Name)
			}
		}
		view.Rows = append(view.Rows, row)
	}
	return view
}
