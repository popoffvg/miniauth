package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

// usersPagePath is the users page. The step-up and each change return here.
const usersPagePath = "/users"

// maxUsersFormBody is large enough for a group name or a resource name, form-encoded.
const maxUsersFormBody = 4 << 10

const (
	msgUsersUnavailable pageMessage = "The users page is not available."
	msgUsersAdminOnly   pageMessage = "Only a member of the admin group can open the users page."
	msgUsersStepUp      pageMessage = "Enter your password again to change users."
	msgUsersFailed      pageMessage = "The user change failed. Try again."
	msgInviteResource   pageMessage = "Choose a resource that exists."
)

// usersPageRequest documents the query of GET /users.
type usersPageRequest struct {
	Q      string `query:"q" description:"Shows only the users whose login or group contains this text."`
	Status string `query:"status" enum:"active,disabled" description:"Shows only the users in this state. Any other value shows every user."`
	Done   string `query:"done" description:"The result of the last change. The page shows a fixed message for a known value and ignores any other value."`
}

// userGroupForm documents the form of POST /users/{login}/groups.
type userGroupForm struct {
	Login string `path:"login"`
	Group string `formData:"group" required:"true" minLength:"1" maxLength:"64"`
}

// userInviteForm documents the form of POST /users/invites.
type userInviteForm struct {
	Resource string `formData:"resource" required:"true"`
}

const usersFormDoc = "Only a member of the group admin can send it; any other user is 403. Origin MUST be the public origin, else 403. A login older than 10 minutes starts a step-up instead: the page asks for the password of the session user and returns to GET /users. A refused change shows the page with a message and 400, 404, or 409."

// usersFormPages are the statuses of a POST of the users page that answer with a page. 200 is the step-up form.
var usersFormPages = []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError, http.StatusServiceUnavailable}

func (s *service) usersPage(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.usersPageAdmin(w, r)
	if !ok {
		return
	}
	s.renderUsers(w, r, http.StatusOK, user, usersPageNote{notice: doneNotice(r)})
}

func (s *service) disableUserForm(w http.ResponseWriter, r *http.Request) {
	s.changeUsers(w, r, doneUserDisabled, func(ctx context.Context, actor useradmin.Actor, login users.Login, _ url.Values) error {
		return s.userAdmin.Disable(ctx, actor, login)
	})
}

func (s *service) enableUserForm(w http.ResponseWriter, r *http.Request) {
	s.changeUsers(w, r, doneUserEnabled, func(ctx context.Context, _ useradmin.Actor, login users.Login, _ url.Values) error {
		return s.userAdmin.Enable(ctx, login)
	})
}

func (s *service) addMemberForm(w http.ResponseWriter, r *http.Request) {
	s.changeUsers(w, r, doneMemberAdded, func(ctx context.Context, _ useradmin.Actor, login users.Login, form url.Values) error {
		name, err := groups.ParseName(form.Get("group"))
		if err != nil {
			return err
		}
		return s.userAdmin.AddToGroup(ctx, login, name)
	})
}

func (s *service) removeMemberForm(w http.ResponseWriter, r *http.Request) {
	s.changeUsers(w, r, doneMemberRemoved, func(ctx context.Context, actor useradmin.Actor, login users.Login, _ url.Values) error {
		name, err := groups.ParseName(r.PathValue("group"))
		if err != nil {
			return err
		}
		return s.userAdmin.RemoveFromGroup(ctx, actor, login, name)
	})
}

// makeInviteForm makes an invite link and shows it once, with Cache-Control: no-store.
func (s *service) makeInviteForm(w http.ResponseWriter, r *http.Request) {
	user, form, ok := s.usersForm(w, r)
	if !ok {
		return
	}
	if s.invites == nil || s.publicURL.Origin() == "" {
		s.renderUsers(w, r, http.StatusServiceUnavailable, user, usersPageNote{message: msgInviteOff})
		return
	}
	resource, err := access.ParseResourceName(form.Get("resource"))
	var invite inviteBody
	if err == nil {
		invite, err = s.makeInvite(r.Context(), resource)
	}
	if errors.Is(err, access.ErrResourceName) || errors.Is(err, access.ErrResourceNotFound) {
		s.renderUsers(w, r, http.StatusBadRequest, user, usersPageNote{message: msgInviteResource})
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: make invite", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgInviteFailed)
		return
	}
	// The link is in this body only. It MUST NOT reach a URL, a log, or a cache.
	w.Header().Set("Cache-Control", "no-store")
	s.renderUsers(w, r, http.StatusOK, user, usersPageNote{invite: invite})
}

// changeUsers runs one change of the users page for an admin and redirects with 303 to the page with done.
// A refused change shows the page with its message.
func (s *service) changeUsers(w http.ResponseWriter, r *http.Request, done doneFlag, change func(ctx context.Context, actor useradmin.Actor, login users.Login, form url.Values) error) {
	user, form, ok := s.usersForm(w, r)
	if !ok {
		return
	}
	login, err := users.ParseLogin(r.PathValue("login"))
	if err == nil {
		err = change(r.Context(), useradmin.Actor{ID: user.ID}, login, form)
	}
	if err != nil {
		if status, detail, known := userAdminProblem(err); known {
			s.renderUsers(w, r, status, user, usersPageNote{message: pageMessage(detail)})
			return
		}
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: users page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgUsersFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+withDone(usersPagePath, done), http.StatusSeeOther)
}

// usersForm runs the checks of a users page POST: Origin, the admin group, then the step-up.
// It returns false after it wrote a reply.
func (s *service) usersForm(w http.ResponseWriter, r *http.Request) (users.User, url.Values, bool) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return users.User{}, nil, false
	}
	user, session, ok := s.usersPageAdmin(w, r)
	if !ok {
		return users.User{}, nil, false
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+usersPagePath), msgUsersStepUp)
		return users.User{}, nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUsersFormBody)
	if r.ParseForm() != nil {
		s.renderUsers(w, r, http.StatusBadRequest, user, usersPageNote{message: msgBadForm})
		return users.User{}, nil, false
	}
	return user, r.PostForm, true
}

func (s *service) usersPageAdmin(w http.ResponseWriter, r *http.Request) (users.User, sessions.Session, bool) {
	if s.userAdmin == nil || s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgUsersUnavailable)
		return users.User{}, sessions.Session{}, false
	}
	return s.adminPageUser(w, r, usersPagePath, msgUsersFailed, msgUsersAdminOnly)
}

// usersPageNote is what one reply of the users page adds to the list: a refusal, a result, or a new invite.
type usersPageNote struct {
	message pageMessage
	notice  pageMessage
	// invite is a new invite link. The zero value shows none.
	invite inviteBody
}

func (s *service) renderUsers(w http.ResponseWriter, r *http.Request, status int, user users.User, note usersPageNote) {
	accounts, err := s.userAdmin.List(r.Context())
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: users page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgUsersFailed)
		return
	}
	view := newUsersPageView(r, accounts, user.Login)
	// The caller checked the admin group, so the menu needs no second lookup.
	view.Shell = shellView{Login: user.Login, Admin: true, Current: usersPagePath}
	view.Message, view.Notice = note.message, note.notice
	view.InvitesOn = s.invites != nil && s.publicURL.Origin() != ""
	if view.InvitesOn && s.accessAdmin != nil {
		if view.Resources, err = s.accessAdmin.ListResources(r.Context()); err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: users page", "err", err)
			renderDenied(w, r, http.StatusInternalServerError, msgUsersFailed)
			return
		}
	}
	view.Invite = note.invite
	writePage(w, r, status, usersPage(view), pageCSP)
}
