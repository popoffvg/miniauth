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
	return views.Shell{Login: user.Login, Admin: slices.Contains(names, groups.Admins()), Current: current}
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
