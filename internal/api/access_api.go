package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/users"
)

// maxAccessBody is large enough for the longest name, URL, and expiry.
const maxAccessBody = 8 << 10

// WithAccessAdmin serves the resource and grant routes under /api/v1. Without it, they answer 503.
func WithAccessAdmin(admin *access.Service) RouterOption {
	return func(s *service) {
		s.accessAdmin = admin
	}
}

// createResourceRequest is the JSON body and the OpenAPI request schema.
// The tags describe the shape. ParseResourceName and ParseResourceURL decide acceptance.
type createResourceRequest struct {
	Name access.ResourceName `json:"name" required:"true" minLength:"1" maxLength:"64" pattern:"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$" doc:"Stored in lower case."`
	URL  access.ResourceURL  `json:"url" required:"true" format:"uri" doc:"An absolute http or https URL with no query. Only the host and the path are stored."`
}

// resourceBody names a resource. URL is the host and the path prefix, with no scheme.
type resourceBody struct {
	Name    access.ResourceName `json:"name"`
	URL     access.ResourceURL  `json:"url" doc:"The host and the path prefix, such as dash.example.test/mcp. The scheme is not stored."`
	Managed bool                `json:"managed" doc:"True for a resource from MINIAUTH_RESOURCES_FILE. The API refuses to delete it: 409."`
}

// grantResourceBody is the resource of a grant.
type grantResourceBody struct {
	Name access.ResourceName `json:"name"`
	URL  access.ResourceURL  `json:"url" doc:"The host and the path prefix. The scheme is not stored."`
}

type resourceList struct {
	Resources []resourceBody `json:"resources" required:"true" nullable:"false"`
}

type resourcePath struct {
	Name access.ResourceName `path:"name"`
}

// createGrantRequest names exactly one of User and Group. The access service checks that.
type createGrantRequest struct {
	Resource  access.ResourceName `json:"resource" required:"true"`
	User      users.Login         `json:"user,omitzero" doc:"The login of the user. Exactly one of user and group."`
	Group     groups.Name         `json:"group,omitzero" doc:"The group name. Exactly one of user and group."`
	ExpiresAt access.Expiry       `json:"expires_at,omitzero" format:"date-time" doc:"RFC 3339. MUST be in the future. Absent: the grant does not expire."`
}

// grantBody is one grant. Exactly one of User and Group is set.
type grantBody struct {
	ID        access.GrantID    `json:"id" format:"uuid"`
	Resource  grantResourceBody `json:"resource"`
	User      users.Login       `json:"user,omitzero"`
	Group     groups.Name       `json:"group,omitzero"`
	ExpiresAt access.Expiry     `json:"expires_at,omitzero" format:"date-time" doc:"Absent: the grant does not expire."`
	CreatedAt time.Time         `json:"created_at"`
	Managed   bool              `json:"managed" doc:"True for a grant from MINIAUTH_RESOURCES_FILE. The API refuses to revoke it: 409."`
}

type grantList struct {
	Grants []grantBody `json:"grants" required:"true" nullable:"false"`
}

type grantPath struct {
	ID access.GrantID `path:"id" format:"uuid"`
}

type listGrantsRequest struct {
	User     users.Login         `query:"user" doc:"Only the grants to this user, not the grants to the user's groups."`
	Resource access.ResourceName `query:"resource" doc:"Only the grants of this resource."`
}

// accessProblem is the reply for one access error.
type accessProblem struct {
	err    error
	status int
	detail string
}

var accessProblems = []accessProblem{
	{err: users.ErrInvalidLogin, status: http.StatusBadRequest, detail: "The login is not valid."},
	{err: groups.ErrName, status: http.StatusBadRequest, detail: "The group name is not valid."},
	{err: access.ErrResourceName, status: http.StatusBadRequest, detail: "The resource name is not valid."},
	{err: access.ErrResourceURL, status: http.StatusBadRequest, detail: "The resource URL MUST be an absolute http or https URL with no query."},
	{err: access.ErrHost, status: http.StatusBadRequest, detail: "The host of the resource URL is not valid."},
	{err: access.ErrPathPrefix, status: http.StatusBadRequest, detail: "The path of the resource URL is not valid."},
	{err: access.ErrSubject, status: http.StatusBadRequest, detail: "Name exactly one of user and group."},
	{err: access.ErrExpiryTime, status: http.StatusBadRequest, detail: "The expiry MUST be an RFC 3339 time."},
	{err: access.ErrExpiry, status: http.StatusBadRequest, detail: "The expiry MUST be in the future."},
	{err: access.ErrUnknownUser, status: http.StatusNotFound, detail: "The user is not found."},
	{err: access.ErrResourceNotFound, status: http.StatusNotFound, detail: "The resource is not found."},
	{err: access.ErrGrantNotFound, status: http.StatusNotFound, detail: "The grant is not found."},
	{err: access.ErrDuplicateResource, status: http.StatusConflict, detail: "A resource with this name or this URL already exists."},
	{err: access.ErrUnknownGroup, status: http.StatusNotFound, detail: "The group is not found."},
	{err: groups.ErrGroupNotFound, status: http.StatusNotFound, detail: "The group is not found."},
	{err: access.ErrDuplicateGrant, status: http.StatusConflict, detail: "The grant already exists."},
	{err: access.ErrManagedResource, status: http.StatusConflict, detail: "The resource comes from the resources file. Change the file and restart miniauth."},
	{err: access.ErrManagedGrant, status: http.StatusConflict, detail: "The grant comes from the resources file. Change the file and restart miniauth."},
}

func writeAccessError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errUnsupportedMedia) || errors.Is(err, errTooLarge) || errors.Is(err, errBadJSON) {
		writeDecodeError(w, err)
		return
	}
	for _, problem := range accessProblems {
		if errors.Is(err, problem.err) {
			writeProblem(w, problem.status, problem.detail)
			return
		}
	}
	loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: access api", "err", err)
	writeProblem(w, http.StatusInternalServerError, "The access change failed.")
}

// accessReady writes 503 and returns false when the router has no access service.
func (s *service) accessReady(w http.ResponseWriter) bool {
	if s.accessAdmin == nil {
		writeProblem(w, http.StatusServiceUnavailable, "The access API is not configured.")
		return false
	}
	return true
}

func (s *service) createResource(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	body, err := decodeJSON[createResourceRequest](w, r, maxAccessBody)
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	created, err := s.accessAdmin.CreateResource(r.Context(), body.Name, body.URL)
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, resourceReply(created))
}

func (s *service) listResources(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	resources, err := s.accessAdmin.ListResources(r.Context())
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	reply := resourceList{Resources: make([]resourceBody, 0, len(resources))}
	for _, resource := range resources {
		reply.Resources = append(reply.Resources, resourceReply(resource))
	}
	writeJSON(w, http.StatusOK, reply)
}

// deleteResource answers 404 for a name that cannot be stored.
func (s *service) deleteResource(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	name, err := access.ParseResourceName(r.PathValue("name"))
	if err != nil {
		writeAccessError(w, r, access.ErrResourceNotFound)
		return
	}
	if err := s.accessAdmin.DeleteResource(r.Context(), name); err != nil {
		writeAccessError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) createGrant(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	body, err := decodeJSON[createGrantRequest](w, r, maxAccessBody)
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	grantee := access.Grantee{User: body.User, Group: body.Group}
	entry, err := s.accessAdmin.GrantTo(r.Context(), body.Resource, grantee, body.ExpiresAt)
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, grantReply(entry))
}

func (s *service) listGrants(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	var filter access.GrantFilter
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "The query is not valid.")
		return
	}
	if raw := query.Get("user"); raw != "" {
		login, loginErr := users.ParseLogin(raw)
		if loginErr != nil {
			writeAccessError(w, r, loginErr)
			return
		}
		filter.User = login
	}
	if raw := query.Get("resource"); raw != "" {
		name, nameErr := access.ParseResourceName(raw)
		if nameErr != nil {
			writeAccessError(w, r, nameErr)
			return
		}
		filter.Resource = name
	}
	entries, err := s.accessAdmin.ListGrants(r.Context(), filter)
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	reply := grantList{Grants: make([]grantBody, 0, len(entries))}
	for _, entry := range entries {
		reply.Grants = append(reply.Grants, grantReply(entry))
	}
	writeJSON(w, http.StatusOK, reply)
}

// revokeGrant answers 404 for an id that is not a UUID.
func (s *service) revokeGrant(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	var id access.GrantID
	if err := id.UnmarshalText([]byte(r.PathValue("id"))); err != nil {
		writeAccessError(w, r, access.ErrGrantNotFound)
		return
	}
	if err := s.accessAdmin.Revoke(r.Context(), id); err != nil {
		writeAccessError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func grantReply(entry access.GrantEntry) grantBody {
	body := grantBody{
		ID:        entry.Grant.ID,
		Resource:  grantResourceBody{Name: entry.Grant.Resource, URL: entry.URL},
		User:      entry.UserLogin,
		ExpiresAt: entry.Grant.Expiry,
		CreatedAt: entry.Grant.CreatedAt,
		Managed:   entry.Grant.Managed,
	}
	if name, ok := entry.Grant.Subject.Group(); ok {
		body.Group = name
	}
	return body
}

func resourceReply(resource access.Resource) resourceBody {
	return resourceBody{Name: resource.Name, URL: resource.URL, Managed: resource.Managed}
}
