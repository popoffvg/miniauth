package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// accessPagePath is the access page. The step-up and each change return here.
const accessPagePath = "/access"

// expiryLocalLayouts are the values of an HTML datetime-local input, read as UTC.
var expiryLocalLayouts = []string{"2006-01-02T15:04", "2006-01-02T15:04:05"}

const (
	msgAccessUnavailable pageMessage = "The access page is not available."
	msgAccessAdminOnly   pageMessage = "Only a member of the admin group can open the access page."
	msgAccessStepUp      pageMessage = "Enter your password again to change access."
	msgAccessFailed      pageMessage = "The access change failed. Try again."
)

// errExpiryInput means the expiry field is not an HTML date or datetime-local value.
var errExpiryInput = errors.New("api: expiry is not a date or a date and time")

// accessPageProblems maps a form or service error to the status and the message of the page.
var accessPageProblems = append([]accessProblem{
	{err: errExpiryInput, status: http.StatusBadRequest, detail: "The expiry MUST be a date or a date and time in UTC."},
}, accessProblems...)

// accessPageRequest documents the query of GET /access.
type accessPageRequest struct {
	Q      string `query:"q" description:"Shows only the resources and the grants whose resource, URL, user, or group contains this text."`
	Status string `query:"status" enum:"active,expired" description:"Shows only the grants in this state. Any other value shows every grant."`
	Done   string `query:"done" description:"The result of the last change. The page shows a fixed message for a known value and ignores any other value."`
}

// accessResourceForm documents the form of POST /access/resources.
type accessResourceForm struct {
	Name string `formData:"name" required:"true" minLength:"1" maxLength:"64"`
	URL  string `formData:"url" required:"true" format:"uri" description:"An absolute http or https URL with no query."`
}

// accessGrantForm documents the form of POST /access/grants.
type accessGrantForm struct {
	Resource string `formData:"resource" required:"true"`
	User     string `formData:"user" description:"A login. Exactly one of user and group."`
	Group    string `formData:"group" description:"A group name. Exactly one of user and group."`
	Expires  string `formData:"expires" description:"An HTML date (the grant works until the end of that UTC day) or datetime-local in UTC. Empty never expires."`
}

type accessResourcePath struct {
	Name string `path:"name"`
}

type accessGrantPath struct {
	ID string `path:"id" format:"uuid"`
}

// accessPage lists the resources and their grants, with the forms that change them.
func (s *service) accessPage(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.accessPageAdmin(w, r)
	if !ok {
		return
	}
	s.renderAccess(w, r, http.StatusOK, user, "", doneNotice(r))
}

func (s *service) addResourceForm(w http.ResponseWriter, r *http.Request) {
	s.changeAccess(w, r, doneResourceAdded, func(ctx context.Context, form url.Values) error {
		name, err := access.ParseResourceName(form.Get("name"))
		if err != nil {
			return err
		}
		target, err := access.ParseResourceURL(form.Get("url"))
		if err != nil {
			return err
		}
		_, err = s.accessAdmin.CreateResource(ctx, name, target)
		return err
	})
}

// deleteResourceForm answers 404 for a name that cannot be stored.
func (s *service) deleteResourceForm(w http.ResponseWriter, r *http.Request) {
	s.changeAccess(w, r, doneResourceDeleted, func(ctx context.Context, _ url.Values) error {
		name, err := access.ParseResourceName(r.PathValue("name"))
		if err != nil {
			return access.ErrResourceNotFound
		}
		return s.accessAdmin.DeleteResource(ctx, name)
	})
}

func (s *service) grantForm(w http.ResponseWriter, r *http.Request) {
	s.changeAccess(w, r, doneGranted, func(ctx context.Context, form url.Values) error {
		resource, err := access.ParseResourceName(form.Get("resource"))
		if err != nil {
			return err
		}
		grantee, err := parseGrantee(form)
		if err != nil {
			return err
		}
		expiry, err := parseExpiryInput(form.Get("expires"))
		if err != nil {
			return err
		}
		_, err = s.accessAdmin.GrantTo(ctx, resource, grantee, expiry)
		return err
	})
}

// revokeForm answers 404 for an id that is not a UUID.
func (s *service) revokeForm(w http.ResponseWriter, r *http.Request) {
	s.changeAccess(w, r, doneGrantRevoked, func(ctx context.Context, _ url.Values) error {
		var id access.GrantID
		if err := id.UnmarshalText([]byte(r.PathValue("id"))); err != nil {
			return access.ErrGrantNotFound
		}
		return s.accessAdmin.Revoke(ctx, id)
	})
}

// changeAccess runs one change of the access page for an admin.
// An AuthAt older than sessions.StepUpAfter starts a step-up first, and the form is sent again after it.
// A change redirects with 303 to the page with done. A refused change shows the page with its message.
func (s *service) changeAccess(w http.ResponseWriter, r *http.Request, done doneFlag, change func(ctx context.Context, form url.Values) error) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	user, session, ok := s.accessPageAdmin(w, r)
	if !ok {
		return
	}
	if !s.browser.AuthRecent(session) {
		s.askStepUp(w, r, user, loginflow.ReturnURL(s.publicURL.Origin()+accessPagePath), msgAccessStepUp)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAccessBody)
	if r.ParseForm() != nil {
		s.renderAccess(w, r, http.StatusBadRequest, user, msgBadForm, "")
		return
	}
	if err := change(r.Context(), r.PostForm); err != nil {
		for _, problem := range accessPageProblems {
			if errors.Is(err, problem.err) {
				s.renderAccess(w, r, problem.status, user, pageMessage(problem.detail), "")
				return
			}
		}
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: access page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgAccessFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+withDone(accessPagePath, done), http.StatusSeeOther)
}

// accessPageAdmin returns the session user when the user is in groups.Admin.
// It returns false after it wrote a reply: a login redirect, 403 for any other user, or an error page.
func (s *service) accessPageAdmin(w http.ResponseWriter, r *http.Request) (users.User, sessions.Session, bool) {
	if s.accessAdmin == nil || s.flows == nil || s.passwords == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgAccessUnavailable)
		return users.User{}, sessions.Session{}, false
	}
	return s.adminPageUser(w, r, accessPagePath, msgAccessFailed, msgAccessAdminOnly)
}

func (s *service) renderAccess(w http.ResponseWriter, r *http.Request, status int, user users.User, message, notice pageMessage) {
	resources, err := s.accessAdmin.ListResources(r.Context())
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: access page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgAccessFailed)
		return
	}
	entries, err := s.accessAdmin.ListGrants(r.Context(), access.GrantFilter{})
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: access page", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgAccessFailed)
		return
	}
	view := newAccessPageView(r, resources, entries, time.Now())
	// The caller checked the admin group, so the menu needs no second lookup.
	view.Shell = shellView{Login: user.Login, Admin: true, Current: accessPagePath}
	view.Message, view.Notice = message, notice
	writePage(w, r, status, accessPage(view), pageCSP)
}

// parseGrantee reads the user and the group fields. The access service checks that exactly one is set.
func parseGrantee(form url.Values) (access.Grantee, error) {
	var grantee access.Grantee
	if raw := strings.TrimSpace(form.Get("user")); raw != "" {
		login, err := users.ParseLogin(raw)
		if err != nil {
			return access.Grantee{}, err
		}
		grantee.User = login
	}
	if raw := strings.TrimSpace(form.Get("group")); raw != "" {
		name, err := groups.ParseName(raw)
		if err != nil {
			return access.Grantee{}, err
		}
		grantee.Group = name
	}
	return grantee, nil
}

// parseExpiryInput reads an HTML date or datetime-local value in UTC. Empty never expires.
// A date expires at the end of that UTC day, the same as a token expiry.
func parseExpiryInput(raw string) (access.Expiry, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return access.Expiry{}, nil
	}
	if day, err := time.Parse(expiryDateLayout, raw); err == nil {
		return access.ExpiresAt(day.AddDate(0, 0, 1)), nil
	}
	for _, layout := range expiryLocalLayouts {
		if at, err := time.Parse(layout, raw); err == nil {
			return access.ExpiresAt(at), nil
		}
	}
	return access.Expiry{}, errExpiryInput
}

// accessFormPages are the statuses of a POST of the access page that answer with a page.
// 200 is the step-up form.
var accessFormPages = []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError, http.StatusServiceUnavailable}

const accessFormDoc = "Only a member of the group admin can send it; any other user is 403. Origin MUST be the public origin, else 403. A login older than 10 minutes starts a step-up instead: the page asks for the password of the session user and returns to GET /access. A refused change shows the page with a message and 400, 404, or 409."
