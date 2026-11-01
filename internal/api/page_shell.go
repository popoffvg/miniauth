package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

// shellFor builds the sidebar of user. A group store error hides the admin menu and is logged:
// the page itself still checks the group before it shows admin data.
func (s *service) shellFor(r *http.Request, user users.User, current views.NavPath) views.Shell {
	names, err := s.groups.List(r.Context(), user.ID)
	if err != nil {
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: page groups", "err", err)
	}
	return s.shell(user, slices.Contains(names, groups.Admins()), current)
}

// shell is the one builder of views.Shell, so every page hides the same menu items.
func (s *service) shell(user users.User, admin bool, current views.NavPath) views.Shell {
	shell := views.Shell{Login: user.Login, Admin: admin, Current: current}
	for _, page := range menuPages {
		if !page.on(s) {
			shell.Off = append(shell.Off, page.path)
		}
	}
	return shell
}

// menuPages is each menu page that needs a service. A page that is off answers 503, so the menu hides it.
var menuPages = []struct {
	path views.NavPath
	on   func(*service) bool
}{
	{path: tokensPath, on: (*service).tokensOn},
	{path: usersPagePath, on: (*service).usersPageOn},
	{path: groupsPagePath, on: (*service).groupsPageOn},
	{path: accessPagePath, on: (*service).accessPageOn},
}

func (s *service) tokensOn() bool {
	return s.tokens != nil && s.flows != nil && s.passwords != nil
}

func (s *service) usersPageOn() bool {
	return s.userAdmin != nil && s.flows != nil && s.passwords != nil
}

func (s *service) groupsPageOn() bool {
	return s.groupAdmin != nil && s.accessAdmin != nil && s.flows != nil && s.passwords != nil
}

func (s *service) accessPageOn() bool {
	return s.accessAdmin != nil && s.flows != nil && s.passwords != nil
}

// matchesQuery reports whether one of fields contains query, ignoring case. An empty query matches.
func matchesQuery(query string, fields ...string) bool {
	if query == "" {
		return true
	}
	query = strings.ToLower(query)
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}
