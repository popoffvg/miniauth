package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// route is one HTTP operation.
// isPublic is false unless the row sets it, so a new row is authenticated.
type route struct {
	method   string
	path     string
	id       string
	handler  http.HandlerFunc
	request  any
	response any
	status   int
	errors   []int
	empty    []int
	doc      string
	isPublic bool
}

// groupList is the groups one user belongs to.
// The forward-auth check calls List and no other method.
type groupList interface {
	List(ctx context.Context, userID users.ID) ([]groups.Name, error)
}

type noGroups struct{}

func (noGroups) List(context.Context, users.ID) ([]groups.Name, error) {
	return nil, nil
}

type service struct {
	accounts  *users.Service
	browser   *sessions.Service
	groups    groupList
	domain    sessions.Domain
	publicURL PublicURL
	admin     AdminTokenHash
	spec      []byte
}

// NewRouter serves the HTTP API.
// admin is the SHA-256 of the bootstrap token.
// domain is the Domain attribute of the session cookie. The zero value is a host-only cookie.
// publicURL is the origin of the login page. The zero value redirects to a path.
// A nil group list means the user has no groups.
func NewRouter(accounts *users.Service, browser *sessions.Service, groups groupList, domain sessions.Domain, publicURL PublicURL, admin AdminTokenHash, logger *slog.Logger) (http.Handler, error) {
	if accounts == nil || browser == nil {
		return nil, errors.New("api: user service or session service is missing")
	}
	if groups == nil {
		groups = noGroups{}
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	apiService := &service{
		accounts:  accounts,
		browser:   browser,
		groups:    groups,
		domain:    domain,
		publicURL: publicURL,
		admin:     admin,
	}
	mux := http.NewServeMux()
	reflector := openapi3.NewReflector()
	reflector.Spec.Info.WithTitle("miniauth").WithVersion("0.0.0")
	reflector.Spec.SetHTTPBearerTokenSecurity(
		"bearerAuth",
		"",
		"Bootstrap admin token. MINIAUTH_ADMIN_TOKEN_SHA256 holds the hex SHA-256 of the token. The token is not in the config.",
	)
	for _, rt := range apiService.routes() {
		handler := rt.handler
		if !rt.isPublic {
			handler = requireAdmin(admin, handler)
		}
		mux.HandleFunc(rt.method+" "+rt.path, handler)
		if err := addOperation(reflector, rt); err != nil {
			return nil, err
		}
	}
	spec, err := reflector.Spec.MarshalYAML()
	if err != nil {
		return nil, fmt.Errorf("api: openapi: %w", err)
	}
	apiService.spec = spec
	return logRequests(logger, mux), nil
}

func (s *service) routes() []route {
	return []route{
		{
			method:   http.MethodGet,
			path:     "/healthz",
			id:       "getHealth",
			handler:  healthz,
			status:   http.StatusNoContent,
			isPublic: true,
		},
		{
			method:   http.MethodGet,
			path:     "/openapi.yaml",
			id:       "getOpenAPI",
			handler:  s.openAPI,
			status:   http.StatusOK,
			response: new(string),
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     "/api/v1/users",
			id:       "createUser",
			handler:  s.createUser,
			request:  new(createUserRequest),
			response: new(createdUser),
			status:   http.StatusCreated,
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusConflict,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
			},
		},
		{
			method:   http.MethodGet,
			path:     "/auth/check",
			id:       "forwardAuth",
			handler:  s.forwardAuth,
			request:  new(forwardAuthRequest),
			status:   http.StatusOK,
			empty:    []int{http.StatusFound, http.StatusUnauthorized, http.StatusForbidden},
			doc:      "Traefik forwardAuth. A valid session answers 200 and sets X-Auth-User, X-Auth-Email, X-Auth-Groups, and X-Auth-Method. A browser with no session is redirected to the login page. Any other request with no session is 401. A user outside group is 403. scope does not limit a session.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     "/logout",
			id:       "logout",
			handler:  s.logout,
			status:   http.StatusNoContent,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     "/logout/everywhere",
			id:       "logoutEverywhere",
			handler:  s.logoutEverywhere,
			status:   http.StatusNoContent,
			errors:   []int{http.StatusUnauthorized},
			isPublic: true,
		},
	}
}

func addOperation(reflector *openapi3.Reflector, rt route) error {
	oc, err := reflector.NewOperationContext(rt.method, rt.path)
	if err != nil {
		return fmt.Errorf("api: openapi: %w", err)
	}
	oc.SetID(rt.id)
	if rt.doc != "" {
		oc.SetDescription(rt.doc)
	}
	if rt.request != nil {
		oc.AddReqStructure(rt.request)
	}
	if rt.response != nil || rt.status != 0 {
		oc.AddRespStructure(rt.response, openapi.WithHTTPStatus(rt.status))
	}
	if !rt.isPublic {
		oc.AddSecurity("bearerAuth")
	}
	for _, status := range rt.empty {
		oc.AddRespStructure(new(struct{}), openapi.WithHTTPStatus(status))
	}
	for _, status := range rt.errors {
		oc.AddRespStructure(new(problemBody), openapi.WithHTTPStatus(status))
	}
	if err := reflector.AddOperation(oc); err != nil {
		return fmt.Errorf("api: openapi: %w", err)
	}
	return nil
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.spec)
}
