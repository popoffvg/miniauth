package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

// WithUserAdmin serves the users admin API and the users page. Without it, they answer 503.
func WithUserAdmin(admin *useradmin.Service) RouterOption {
	return func(s *service) {
		s.userAdmin = admin
	}
}

// userListBody is the 200 body of GET /api/v1/users.
type userListBody struct {
	Users []userAccountBody `json:"users" required:"true" nullable:"false"`
}

type userAccountBody struct {
	Login      users.Login   `json:"login"`
	Groups     []groups.Name `json:"groups" required:"true" nullable:"false"`
	Disabled   bool          `json:"disabled"`
	DisabledAt time.Time     `json:"disabled_at,omitzero" doc:"Absent for an active user."`
	CreatedAt  time.Time     `json:"created_at"`
	Devices    int           `json:"devices" doc:"The browsers that signed in to the account."`
	LastSeen   time.Time     `json:"last_seen,omitzero" doc:"The last time a device of the user was seen. Absent when no device is known."`
}

type userLoginPath struct {
	Login string `path:"login"`
}

type groupMemberPath struct {
	Group string `path:"group"`
	Login string `path:"login"`
}

// userAdminProblems maps a service error to the status and the message of the API and of the page.
var userAdminProblems = []struct {
	err    error
	status int
	detail string
}{
	{err: users.ErrInvalidLogin, status: http.StatusBadRequest, detail: "The login is not valid."},
	{err: groups.ErrName, status: http.StatusBadRequest, detail: "The group name is not valid."},
	{err: useradmin.ErrUserNotFound, status: http.StatusNotFound, detail: "The user is not found."},
	{err: groups.ErrGroupNotFound, status: http.StatusNotFound, detail: "The group is not found. Create it on the groups page first."},
	{err: useradmin.ErrNotMember, status: http.StatusNotFound, detail: "The user is not in the group."},
	{err: useradmin.ErrSelfDisable, status: http.StatusConflict, detail: "You cannot disable your own account."},
	{err: useradmin.ErrSelfAdmin, status: http.StatusConflict, detail: "You cannot remove yourself from the admins group."},
	{err: sfsm.ErrStaleState, status: http.StatusConflict, detail: "Another request changed the user at the same moment. Load the user again and try again."},
}

// userAdminProblem returns false for an error that is not in userAdminProblems.
func userAdminProblem(err error) (int, string, bool) {
	for _, problem := range userAdminProblems {
		if errors.Is(err, problem.err) {
			return problem.status, problem.detail, true
		}
	}
	return 0, "", false
}

func (s *service) userAdminReady(w http.ResponseWriter) bool {
	if s.userAdmin == nil {
		writeProblem(w, http.StatusServiceUnavailable, "The users admin API is not configured.")
		return false
	}
	return true
}

func (s *service) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.userAdminReady(w) {
		return
	}
	accounts, err := s.userAdmin.List(r.Context())
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: list users", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The users were not loaded.")
		return
	}
	body := userListBody{Users: make([]userAccountBody, 0, len(accounts))}
	for _, account := range accounts {
		body.Users = append(body.Users, userAccountBody{
			Login:      account.User.Login,
			Groups:     append([]groups.Name{}, account.Groups...),
			Disabled:   account.User.Disabled(),
			DisabledAt: account.User.DisabledAt,
			CreatedAt:  account.User.CreatedAt,
			Devices:    account.Devices,
			LastSeen:   account.LastSeen,
		})
	}
	writeJSON(w, http.StatusOK, body)
}

// disableUserAPI acts as the zero useradmin.Actor: the bootstrap token is no user.
func (s *service) disableUserAPI(w http.ResponseWriter, r *http.Request) {
	s.changeUserAPI(w, r, func(ctx context.Context, login users.Login) error {
		return s.userAdmin.Disable(ctx, useradmin.Actor{}, login)
	})
}

func (s *service) enableUserAPI(w http.ResponseWriter, r *http.Request) {
	s.changeUserAPI(w, r, func(ctx context.Context, login users.Login) error {
		return s.userAdmin.Enable(ctx, useradmin.Actor{}, login)
	})
}

func (s *service) addMemberAPI(w http.ResponseWriter, r *http.Request) {
	s.changeUserAPI(w, r, func(ctx context.Context, login users.Login) error {
		name, err := groups.ParseName(r.PathValue("group"))
		if err != nil {
			return err
		}
		return s.userAdmin.AddToGroup(ctx, login, name)
	})
}

func (s *service) removeMemberAPI(w http.ResponseWriter, r *http.Request) {
	s.changeUserAPI(w, r, func(ctx context.Context, login users.Login) error {
		name, err := groups.ParseName(r.PathValue("group"))
		if err != nil {
			return err
		}
		return s.userAdmin.RemoveFromGroup(ctx, useradmin.Actor{}, login, name)
	})
}

// changeUserAPI runs change for the login in the path and answers 204.
func (s *service) changeUserAPI(w http.ResponseWriter, r *http.Request, change func(ctx context.Context, login users.Login) error) {
	if !s.userAdminReady(w) {
		return
	}
	login, err := users.ParseLogin(r.PathValue("login"))
	if err == nil {
		err = change(r.Context(), login)
	}
	if err != nil {
		if status, detail, ok := userAdminProblem(err); ok {
			writeProblem(w, status, detail)
			return
		}
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: users admin api", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The user change failed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
