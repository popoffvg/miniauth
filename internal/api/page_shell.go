package api

import (
	"net/http"
	"slices"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// shellView is the sidebar of a signed-in page: the user, the menu, and the item of this page.
type shellView struct {
	Login   users.Login
	Admin   bool
	Current navPath
}

// navPath is the path of one menu item.
type navPath string

// navSection is a heading of the menu.
type navSection string

const (
	navAccount navSection = "Account"
	// navAdministration is shown only to a member of groups.Admin.
	navAdministration navSection = "Administration"
)

// navItem is one link of the menu.
type navItem struct {
	Path    navPath
	Section navSection
	Label   string
	Icon    iconName
}

// navItems is the menu, in the order of the sidebar.
var navItems = []navItem{
	{Path: "/", Section: navAccount, Label: "Overview", Icon: iconHome},
	{Path: tokensPath, Section: navAccount, Label: "Tokens", Icon: iconKey},
	{Path: sessionsPagePath, Section: navAccount, Label: "Security", Icon: iconShield},
	{Path: accessPagePath, Section: navAdministration, Label: "Access", Icon: iconLock},
}

// navSections is the order of the menu headings.
var navSections = []navSection{navAccount, navAdministration}

// itemsOf returns the menu items of section that shell may see.
func (shell shellView) itemsOf(section navSection) []navItem {
	if section == navAdministration && !shell.Admin {
		return nil
	}
	var items []navItem
	for _, item := range navItems {
		if item.Section == section {
			items = append(items, item)
		}
	}
	return items
}

// shellFor builds the sidebar of user. A group store error hides the admin menu and is logged:
// the page itself still checks the group before it shows admin data.
func (s *service) shellFor(r *http.Request, user users.User, current navPath) shellView {
	names, err := s.groups.List(r.Context(), user.ID)
	if err != nil {
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: page groups", "err", err)
	}
	return shellView{Login: user.Login, Admin: slices.Contains(names, groups.Admin()), Current: current}
}
