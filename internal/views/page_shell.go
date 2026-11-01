package views

import (
	"github.com/popoffvg/miniauth/internal/users"
)

// Shell is the sidebar of a signed-in page: the user, the menu, and the item of this page.
type Shell struct {
	Login   users.Login
	Admin   bool
	Current NavPath
}

// NavPath is the path of one menu item.
type NavPath string

// navSection is a heading of the menu.
type navSection string

const (
	navAccount navSection = "Account"
	// navAdministration is shown only to a member of groups.Admins.
	navAdministration navSection = "Administration"
)

// navItem is one link of the menu.
type navItem struct {
	Path    NavPath
	Section navSection
	Label   string
	Icon    Icon
}

// navItems is the menu, in the order of the sidebar.
var navItems = []navItem{
	{Path: "/", Section: navAccount, Label: "Overview", Icon: IconHome},
	{Path: TokensPath, Section: navAccount, Label: "Tokens", Icon: IconKey},
	{Path: SecurityPath, Section: navAccount, Label: "Security", Icon: IconShield},
	{Path: UsersPath, Section: navAdministration, Label: "Users", Icon: IconUsers},
	{Path: GroupsPath, Section: navAdministration, Label: "Groups", Icon: IconGroups},
	{Path: AccessPath, Section: navAdministration, Label: "Access", Icon: IconLock},
}

// navSections is the order of the menu headings.
var navSections = []navSection{navAccount, navAdministration}

// itemsOf returns the menu items of section that shell may see.
func (shell Shell) itemsOf(section navSection) []navItem {
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
