package api

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
)

// groupRow is one group of the table. Addable is every resource the group does not have yet.
type groupRow struct {
	Group   groupadmin.Group
	Addable []access.ResourceName
}

// groupsPageView is the data of the groups page. Rows pass the search; Total counts every group.
type groupsPageView struct {
	Shell   shellView
	Message pageMessage
	Notice  pageMessage
	Query   string
	Rows    []groupRow
	Total   int
}

func newGroupsPageView(r *http.Request, found []groupadmin.Group, resources []access.Resource) groupsPageView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	view := groupsPageView{Query: query, Total: len(found)}
	for _, group := range found {
		fields := []string{group.Name.String()}
		for _, resource := range group.Resources {
			fields = append(fields, resource.Name.String())
		}
		if !matchesQuery(query, fields...) {
			continue
		}
		row := groupRow{Group: group}
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

// canDelete is false for a group the service refuses to delete, so the page does not offer it.
func (row groupRow) canDelete() bool {
	return !row.Group.BuiltIn && !row.Group.Managed()
}

// actionPath is the path of a POST on the group of row.
func (row groupRow) actionPath(action string) string {
	return groupsPagePath + "/" + url.PathEscape(row.Group.Name.String()) + "/" + action
}
