package api

import (
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

func newUsersPageView(r *http.Request, accounts []useradmin.Account, self users.Login) views.UsersView {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := views.UserFilter(r.URL.Query().Get("status"))
	if filter != views.UserFilterActive && filter != views.UserFilterDisabled {
		filter = ""
	}
	view := views.UsersView{Query: query, Filter: filter, Total: len(accounts)}
	for _, account := range accounts {
		disabled := account.User.Disabled()
		if filter == views.UserFilterActive && disabled || filter == views.UserFilterDisabled && !disabled {
			continue
		}
		fields := []string{account.User.Login.String()}
		for _, name := range account.Groups {
			fields = append(fields, name.String())
		}
		if !matchesQuery(query, fields...) {
			continue
		}
		view.Rows = append(view.Rows, views.UserRow{Account: account, Self: account.User.Login == self})
	}
	return view
}
