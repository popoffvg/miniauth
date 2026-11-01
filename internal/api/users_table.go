package api

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

// userFilter is the status filter of the users table. Empty shows every user.
type userFilter string

const (
	userFilterActive   userFilter = "active"
	userFilterDisabled userFilter = "disabled"
)

var userChips = []filterChip{
	{Value: "", Label: "All"},
	{Value: string(userFilterActive), Label: "Active"},
	{Value: string(userFilterDisabled), Label: "Disabled"},
}

// userRow is one user of the table. Self is the admin who views the page: the page offers no
// action that the service refuses for the actor.
type userRow struct {
	Account useradmin.Account
	Self    bool
}

// joinable returns the groups of choices that the user is not in.
func (row userRow) joinable(choices []groups.Name) []groups.Name {
	var found []groups.Name
	for _, name := range choices {
		if !slices.Contains(row.Account.Groups, name) {
			found = append(found, name)
		}
	}
	return found
}

func (row userRow) canLeave(name groups.Name) bool {
	return !row.Self || name != groups.Admins()
}

// usersPageView is the data of the users page. Rows pass the search and the filter; Total counts every user.
type usersPageView struct {
	Shell     shellView
	Message   pageMessage
	Notice    pageMessage
	Query     string
	Filter    userFilter
	Rows      []userRow
	Total     int
	InvitesOn bool
	// Groups is every group, for the add-to-group menu and the invite form.
	Groups []groups.Name
	// Invite is set only on the reply of POST /users/invites. The handler MUST set Cache-Control: no-store.
	Invite inviteBody
}

func newUsersPageView(r *http.Request, accounts []useradmin.Account, self users.Login) usersPageView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := userFilter(r.URL.Query().Get("status"))
	if filter != userFilterActive && filter != userFilterDisabled {
		filter = ""
	}
	view := usersPageView{Query: query, Filter: filter, Total: len(accounts)}
	for _, account := range accounts {
		disabled := account.User.Disabled()
		if filter == userFilterActive && disabled || filter == userFilterDisabled && !disabled {
			continue
		}
		fields := []string{account.User.Login.String()}
		for _, name := range account.Groups {
			fields = append(fields, name.String())
		}
		if !matchesQuery(query, fields...) {
			continue
		}
		view.Rows = append(view.Rows, userRow{Account: account, Self: account.User.Login == self})
	}
	return view
}

// actionPath is the path of a POST on the user of row. The login is path-escaped: a login can hold "@" and "+".
func (row userRow) actionPath(action string) string {
	return usersPagePath + "/" + url.PathEscape(row.Account.User.Login.String()) + "/" + action
}
