package api

import (
	"context"
	"net/http"
	"net/url"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

// groupsPagePath is the groups page. The step-up and each change return here.
const groupsPagePath = views.GroupsPath

const (
	msgGroupsUnavailable views.Message = "The groups page is not available."
	msgGroupsAdminOnly   views.Message = "Only a member of the admins group can open the groups page."
	msgGroupsStepUp      views.Message = "Enter your password again to change groups."
	msgGroupsFailed      views.Message = "The group change failed. Try again."
)

// groupsPageRequest documents the query of GET /groups.
type groupsPageRequest struct {
	Q    string `query:"q" description:"Shows only the groups whose name or resource contains this text."`
	Done string `query:"done" description:"The result of the last change. The page shows a fixed message for a known value and ignores any other value."`
}

// groupForm documents the form of POST /groups.
type groupForm struct {
	Name string `formData:"name" required:"true" minLength:"1" maxLength:"64"`
}

// groupResourceForm documents the form of POST /groups/{group}/resources.
type groupResourceForm struct {
	Group    string `path:"group"`
	Resource string `formData:"resource" required:"true"`
}

const groupsFormDoc = "Only a member of the group admins can send it; any other user is 403. Origin MUST be the public origin, else 403. A login older than 10 minutes starts a step-up instead: the page asks for the password of the session user and returns to GET /groups. A refused change shows the page with a message and 400, 404, or 409."

// groupsFormPages are the statuses of a POST of the groups page that answer with a page. 200 is the step-up form.
var groupsFormPages = []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError, http.StatusServiceUnavailable}

func (s *service) groupsPage(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.groupsPageAdmin(w, r)
	if !ok {
		return
	}
	s.renderGroups(w, r, http.StatusOK, user, "", doneNotice(r))
}

func (s *service) createGroupForm(w http.ResponseWriter, r *http.Request) {
	s.changeGroups(w, r, doneGroupCreated, func(ctx context.Context, form url.Values) error {
		name, err := groups.ParseName(form.Get("name"))
		if err != nil {
			return err
		}
		_, err = s.groupAdmin.Create(ctx, name)
		return err
	})
}

// deleteGroupForm answers 404 for a name that cannot be stored.
func (s *service) deleteGroupForm(w http.ResponseWriter, r *http.Request) {
	s.changeGroups(w, r, doneGroupDeleted, func(ctx context.Context, _ url.Values) error {
		name, err := groups.ParseName(r.PathValue("group"))
		if err != nil {
			return groups.ErrGroupNotFound
		}
		return s.groupAdmin.Delete(ctx, name)
	})
}

func (s *service) addGroupResourceForm(w http.ResponseWriter, r *http.Request) {
	s.changeGroups(w, r, doneGroupResourceAdded, func(ctx context.Context, form url.Values) error {
		name, err := groups.ParseName(r.PathValue("group"))
		if err != nil {
			return groups.ErrGroupNotFound
		}
		resource, err := access.ParseResourceName(form.Get("resource"))
		if err != nil {
			return err
		}
		return s.groupAdmin.AddResource(ctx, name, resource)
	})
}

func (s *service) removeGroupResourceForm(w http.ResponseWriter, r *http.Request) {
	s.changeGroups(w, r, doneGroupResourceRemoved, func(ctx context.Context, _ url.Values) error {
		name, err := groups.ParseName(r.PathValue("group"))
		if err != nil {
			return groups.ErrGroupNotFound
		}
		resource, err := access.ParseResourceName(r.PathValue("name"))
		if err != nil {
			return access.ErrResourceNotFound
		}
		return s.groupAdmin.RemoveResource(ctx, name, resource)
	})
}

// changeGroups runs one change of the groups page for an admin: Origin, the admins group, the step-up,
// then the service. A change redirects with 303 to the page with done. A refused change shows the page with its message.
func (s *service) changeGroups(w http.ResponseWriter, r *http.Request, done doneFlag, change func(ctx context.Context, form url.Values) error) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	user, session, ok := s.groupsPageAdmin(w, r)
	if !ok {
		return
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+groupsPagePath), msgGroupsStepUp)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUsersFormBody)
	if r.ParseForm() != nil {
		s.renderGroups(w, r, http.StatusBadRequest, user, msgBadForm, "")
		return
	}
	if err := change(r.Context(), r.PostForm); err != nil {
		if status, detail, known := groupAdminProblem(err); known {
			s.renderGroups(w, r, status, user, views.Message(detail), "")
			return
		}
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: groups page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgGroupsFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+withDone(groupsPagePath, done), http.StatusSeeOther)
}

func (s *service) groupsPageAdmin(w http.ResponseWriter, r *http.Request) (users.User, sessions.Session, bool) {
	if !s.groupsPageOn() {
		renderDenied(w, r, http.StatusServiceUnavailable, msgGroupsUnavailable)
		return users.User{}, sessions.Session{}, false
	}
	return s.adminPageUser(w, r, groupsPagePath, msgGroupsFailed, msgGroupsAdminOnly)
}

func (s *service) renderGroups(w http.ResponseWriter, r *http.Request, status int, user users.User, message, notice views.Message) {
	found, err := s.groupAdmin.List(r.Context())
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: groups page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgGroupsFailed)
		return
	}
	resources, err := s.accessAdmin.ListResources(r.Context())
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: groups page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgGroupsFailed)
		return
	}
	view := newGroupsPageView(r, found, resources)
	// The caller checked the admins group, so the menu needs no second lookup.
	view.Shell = s.shell(user, true, groupsPagePath)
	view.Message, view.Notice = message, notice
	writePage(w, r, status, views.GroupsPage(view), pageCSP)
}
