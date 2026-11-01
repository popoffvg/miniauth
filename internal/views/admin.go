package views

import (
	"net/url"
	"slices"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/useradmin"
)

// UserFilter is the status filter of the users table. Empty shows every user.
type UserFilter string

// The user filters. Each is the value of the status query of GET /users.
const (
	UserFilterActive   UserFilter = "active"
	UserFilterDisabled UserFilter = "disabled"
)

var userChips = []FilterChip{
	{Value: "", Label: "All"},
	{Value: string(UserFilterActive), Label: "Active"},
	{Value: string(UserFilterDisabled), Label: "Disabled"},
}

// UserRow is one user of the table. Self is the admin who views the page: the page offers no
// action that the service refuses for the actor.
type UserRow struct {
	Account useradmin.Account
	Self    bool
}

// joinable returns the groups of choices that the user is not in.
func (row UserRow) joinable(choices []groups.Name) []groups.Name {
	var found []groups.Name
	for _, name := range choices {
		if !slices.Contains(row.Account.Groups, name) {
			found = append(found, name)
		}
	}
	return found
}

func (row UserRow) canLeave(name groups.Name) bool {
	return !row.Self || name != groups.Admins()
}

// actionPath is the path of a POST on the user of row. The login is path-escaped: a login can hold "@" and "+".
func (row UserRow) actionPath(action string) string {
	return UsersPath + "/" + url.PathEscape(row.Account.User.Login.String()) + "/" + action
}

// InviteLink is the one-time link of an invite. It holds the token.
type InviteLink string

// Invite is a new invite link that a page shows once. The zero value shows none.
type Invite struct {
	Link      InviteLink
	Group     groups.Name
	ExpiresAt time.Time
}

// UsersView is the data of the users page. Rows pass the search and the filter; Total counts every user.
type UsersView struct {
	Shell     Shell
	Message   Message
	Notice    Message
	Query     string
	Filter    UserFilter
	Rows      []UserRow
	Total     int
	InvitesOn bool
	// Groups is every group, for the add-to-group menu and the invite form.
	Groups []groups.Name
	// Invite is set only on the reply of POST /users/invites. The handler MUST set Cache-Control: no-store.
	Invite Invite
}

// GroupRow is one group of the table. Addable is every resource the group does not have yet.
type GroupRow struct {
	Group   groupadmin.Group
	Addable []access.ResourceName
}

// canDelete is false for a group the service refuses to delete, so the page does not offer it.
func (row GroupRow) canDelete() bool {
	return !row.Group.BuiltIn && !row.Group.Managed()
}

// actionPath is the path of a POST on the group of row.
func (row GroupRow) actionPath(action string) string {
	return GroupsPath + "/" + url.PathEscape(row.Group.Name.String()) + "/" + action
}

// GroupsView is the data of the groups page. Rows pass the search; Total counts every group.
type GroupsView struct {
	Shell   Shell
	Message Message
	Notice  Message
	Query   string
	Rows    []GroupRow
	Total   int
}
