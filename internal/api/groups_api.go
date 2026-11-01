package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
)

// maxGroupBody is large enough for the longest group name.
const maxGroupBody = 1 << 10

// WithGroupAdmin serves the groups API and the groups page. Without it, they answer 503.
func WithGroupAdmin(admin *groupadmin.Service) RouterOption {
	return func(s *service) {
		s.groupAdmin = admin
	}
}

type createGroupRequest struct {
	Name groups.Name `json:"name" required:"true" minLength:"1" maxLength:"64" pattern:"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$" doc:"Stored in lower case."`
}

type groupListBody struct {
	Groups []groupBody `json:"groups" required:"true" nullable:"false"`
}

type groupBody struct {
	Name      groups.Name         `json:"name"`
	BuiltIn   bool                `json:"built_in" doc:"True for admins and users. A built-in group cannot be deleted."`
	Members   int                 `json:"members"`
	Resources []groupResourceBody `json:"resources" required:"true" nullable:"false"`
	CreatedAt time.Time           `json:"created_at"`
}

type groupResourceBody struct {
	Name    access.ResourceName `json:"name"`
	Managed bool                `json:"managed" doc:"True for a grant from MINIAUTH_RESOURCES_FILE. The API refuses to remove it: 409."`
}

type groupPath struct {
	Group string `path:"group"`
}

type groupResourcePath struct {
	Group string `path:"group"`
	Name  string `path:"name"`
}

// groupAdminProblems maps a groups service error to the status and the message of the API and of the page.
var groupAdminProblems = append([]accessProblem{
	{err: groups.ErrGroupNotFound, status: http.StatusNotFound, detail: "The group is not found."},
	{err: groups.ErrDuplicateGroup, status: http.StatusConflict, detail: "A group with this name already exists."},
	{err: groups.ErrBuiltIn, status: http.StatusConflict, detail: "The groups admins and users are built in. They cannot be deleted."},
	{err: groupadmin.ErrManagedGroup, status: http.StatusConflict, detail: "The resources file gives this group a resource. Remove the group from the file and restart miniauth first."},
	{err: groupadmin.ErrNotGranted, status: http.StatusNotFound, detail: "The group does not have this resource."},
}, accessProblems...)

// groupAdminProblem returns false for an error that is not in groupAdminProblems.
func groupAdminProblem(err error) (int, string, bool) {
	for _, problem := range groupAdminProblems {
		if errors.Is(err, problem.err) {
			return problem.status, problem.detail, true
		}
	}
	return 0, "", false
}

func (s *service) groupAdminReady(w http.ResponseWriter) bool {
	if s.groupAdmin == nil {
		writeProblem(w, http.StatusServiceUnavailable, "The groups API is not configured.")
		return false
	}
	return true
}

func (s *service) listGroups(w http.ResponseWriter, r *http.Request) {
	if !s.groupAdminReady(w) {
		return
	}
	found, err := s.groupAdmin.List(r.Context())
	if err != nil {
		writeGroupError(w, r, err)
		return
	}
	body := groupListBody{Groups: make([]groupBody, 0, len(found))}
	for _, group := range found {
		body.Groups = append(body.Groups, groupReply(group))
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *service) createGroup(w http.ResponseWriter, r *http.Request) {
	if !s.groupAdminReady(w) {
		return
	}
	body, err := decodeJSON[createGroupRequest](w, r, maxGroupBody)
	var created groupadmin.Group
	if err == nil {
		created, err = s.groupAdmin.Create(r.Context(), body.Name)
	}
	if err != nil {
		writeGroupError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, groupReply(created))
}

func (s *service) deleteGroup(w http.ResponseWriter, r *http.Request) {
	s.changeGroupAPI(w, r, func(ctx context.Context, name groups.Name) error {
		return s.groupAdmin.Delete(ctx, name)
	})
}

func (s *service) addGroupResource(w http.ResponseWriter, r *http.Request) {
	s.changeGroupAPI(w, r, func(ctx context.Context, name groups.Name) error {
		resource, err := access.ParseResourceName(r.PathValue("name"))
		if err != nil {
			return err
		}
		return s.groupAdmin.AddResource(ctx, name, resource)
	})
}

func (s *service) removeGroupResource(w http.ResponseWriter, r *http.Request) {
	s.changeGroupAPI(w, r, func(ctx context.Context, name groups.Name) error {
		resource, err := access.ParseResourceName(r.PathValue("name"))
		if err != nil {
			return err
		}
		return s.groupAdmin.RemoveResource(ctx, name, resource)
	})
}

// changeGroupAPI runs change for the group in the path and answers 204.
func (s *service) changeGroupAPI(w http.ResponseWriter, r *http.Request, change func(ctx context.Context, name groups.Name) error) {
	if !s.groupAdminReady(w) {
		return
	}
	name, err := groups.ParseName(r.PathValue("group"))
	if err == nil {
		err = change(r.Context(), name)
	}
	if err != nil {
		writeGroupError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeGroupError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errUnsupportedMedia) || errors.Is(err, errTooLarge) || errors.Is(err, errBadJSON) {
		writeDecodeError(w, err)
		return
	}
	if status, detail, ok := groupAdminProblem(err); ok {
		writeProblem(w, status, detail)
		return
	}
	loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: groups api", "err", err)
	writeProblem(w, http.StatusInternalServerError, "The group change failed.")
}

func groupReply(group groupadmin.Group) groupBody {
	body := groupBody{Name: group.Name, BuiltIn: group.BuiltIn, Members: group.Members, CreatedAt: group.CreatedAt, Resources: []groupResourceBody{}}
	for _, resource := range group.Resources {
		body.Resources = append(body.Resources, groupResourceBody{Name: resource.Name, Managed: resource.Managed})
	}
	return body
}
