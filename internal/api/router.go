package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
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
	// contentType is the media type of the response body. Empty is JSON.
	contentType string
	// pages are the other statuses that answer with an HTML page.
	pages    []int
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
	grants    urlAccess
	domain    sessions.Domain
	publicURL PublicURL
	admin     AdminTokenHash
	tokens    *tokens.Service
	ready     Readiness
	flows     *loginflow.LoginFlows
	passwords *passwordstep.Service
	spec      []byte
}

// WithLogin serves the login page. Without it, the login routes answer 503.
func WithLogin(flows *loginflow.LoginFlows, passwords *passwordstep.Service) RouterOption {
	return func(s *service) {
		s.flows = flows
		s.passwords = passwords
	}
}

// Readiness reports whether the process can take traffic.
// GET /readyz returns 200 only when Ready returns true.
type Readiness interface {
	Ready() bool
}

// NewRouter serves the HTTP API.
// admin is the SHA-256 of the bootstrap token.
// domain is the Domain attribute of the session cookie. The zero value is a host-only cookie.
// publicURL is the origin of the login page. The zero value redirects to a path.
// A nil group list means the user has no groups.
// ready decides GET /readyz. A nil ready value fails closed: /readyz returns 503.
func NewRouter(accounts *users.Service, browser *sessions.Service, groups groupList, domain sessions.Domain, publicURL PublicURL, admin AdminTokenHash, ready Readiness, logger *slog.Logger, options ...RouterOption) (http.Handler, error) {
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
		ready:     ready,
	}
	for _, option := range options {
		option(apiService)
	}
	if apiService.grants == nil {
		apiService.grants = noGrants{}
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
			path:     "/readyz",
			id:       "getReady",
			handler:  s.readyz,
			status:   http.StatusOK,
			empty:    []int{http.StatusServiceUnavailable},
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
			doc:      "Traefik forwardAuth. A valid session or a valid Authorization: Bearer idp_ token answers 200 and sets X-Auth-User, X-Auth-Email, X-Auth-Groups, and X-Auth-Method. A browser with no session is redirected to the login page. Any other request with no session is 401. An invalid, revoked, or expired token, or a token of a disabled user, is 401 with error=\"invalid_token\". A URL under no scope of the token is 403. A user outside group is 403. The URL in X-Forwarded-Proto, X-Forwarded-Host, and X-Forwarded-Uri needs a resource and an active grant for the user or one of the user's groups, for a session and for a token; else 403. The scope query does not limit a session.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        "/login",
			id:          "loginPage",
			handler:     s.loginPage,
			request:     new(loginPageRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Starts a login flow and shows the login form. The flow id and secret go to the HttpOnly cookie __Host-id_login_flow.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     "/login",
			id:       "login",
			handler:  s.login,
			request:  new(loginFormRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Checks the password for the flow in the login flow cookie. Origin MUST be the public origin, else 403. A complete flow sets the session cookie and redirects to the return URL. A wrong login or password shows the form again with 200. A backoff is 429.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        "/{$}",
			id:          "home",
			handler:     s.home,
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusFound},
			doc:         "The default page after a login. It shows the login of the session. With no session it redirects to the login page.",
			isPublic:    true,
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
		{
			method:      http.MethodGet,
			path:        sessionsPagePath,
			id:          "listDevices",
			handler:     s.sessionsPage,
			response:    new(string),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusFound},
			errors:      []int{http.StatusUnauthorized},
			doc:         "HTML page with the devices of the session user. A browser with no session is redirected to the login page. Any other request with no session is 401.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     "/sessions/{device}/signout",
			id:       "signOutDevice",
			handler:  s.signOutDevice,
			request:  new(deviceRequest),
			status:   http.StatusSeeOther,
			errors:   []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
			doc:      "Deletes the session of a device of the session user. The device stays. Origin MUST be the public URL origin, else 403. Redirects to the sessions page.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     "/sessions/{device}/forget",
			id:       "forgetDevice",
			handler:  s.forgetDevice,
			request:  new(deviceRequest),
			status:   http.StatusSeeOther,
			errors:   []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
			doc:      "Deletes a device of the session user and its session. Origin MUST be the public URL origin, else 403. Redirects to the sessions page.",
			isPublic: true,
		},
	}
}

func addOperation(reflector *openapi3.Reflector, rt route) error {
	// The mux suffix {$} matches only the exact path. OpenAPI has no such syntax.
	oc, err := reflector.NewOperationContext(rt.method, strings.TrimSuffix(rt.path, "{$}"))
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
		oc.AddRespStructure(rt.response, openapi.WithHTTPStatus(rt.status), withContentType(rt.contentType))
	}
	if !rt.isPublic {
		oc.AddSecurity("bearerAuth")
	}
	for _, status := range rt.empty {
		oc.AddRespStructure(new(struct{}), openapi.WithHTTPStatus(status))
	}
	for _, status := range rt.pages {
		oc.AddRespStructure(new(htmlPage), openapi.WithHTTPStatus(status), openapi.WithContentType("text/html"))
	}
	for _, status := range rt.errors {
		oc.AddRespStructure(new(problemBody), openapi.WithHTTPStatus(status))
	}
	if err := reflector.AddOperation(oc); err != nil {
		return fmt.Errorf("api: openapi: %w", err)
	}
	return nil
}

// withContentType keeps the default JSON media type when contentType is empty.
func withContentType(contentType string) openapi.ContentOption {
	return func(cu *openapi.ContentUnit) {
		if contentType != "" {
			cu.ContentType = contentType
		}
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// readyz is the readiness probe.
// It returns 200 only when the process is in the Ready state.
func (s *service) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.ready != nil && s.ready.Ready() {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (s *service) openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.spec)
}
