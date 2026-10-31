package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

// route is one HTTP operation.
// public is false unless the row sets it, so a new row is authenticated.
type route struct {
	method   string
	path     string
	id       string
	handler  http.HandlerFunc
	request  any
	response any
	status   int
	errors   []int
	public   bool
	// more lists extra statuses that have an empty body.
	more []int
}

type service struct {
	accounts *users.Service
	browser  *sessions.Service
	domain   sessions.Domain
	admin    AdminTokenHash
	ready    Readiness
	spec     []byte
}

// Readiness reports whether the process can take traffic.
// GET /readyz returns 200 only when Ready returns true.
type Readiness interface {
	Ready() bool
}

// NewRouter serves the HTTP API.
// admin is the SHA-256 of the bootstrap token.
// domain is the Domain attribute of the session cookie. The zero value is a host-only cookie.
// ready decides GET /readyz. A nil ready value fails closed: /readyz returns 503.
func NewRouter(accounts *users.Service, browser *sessions.Service, domain sessions.Domain, admin AdminTokenHash, ready Readiness, logger *slog.Logger) (http.Handler, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	svc := &service{accounts: accounts, browser: browser, domain: domain, admin: admin, ready: ready}
	mux := http.NewServeMux()
	reflector := openapi3.NewReflector()
	reflector.Spec.Info.WithTitle("miniauth").WithVersion("0.0.0")
	reflector.Spec.SetHTTPBearerTokenSecurity(
		"bearerAuth",
		"",
		"Bootstrap admin token. MINIAUTH_ADMIN_TOKEN_SHA256 holds the hex SHA-256 of the token. The token is not in the config.",
	)
	for _, rt := range svc.routes() {
		handler := rt.handler
		if !rt.public {
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
	svc.spec = spec
	return logRequests(logger, mux), nil
}

func (s *service) routes() []route {
	return []route{
		{
			method:  http.MethodGet,
			path:    "/healthz",
			id:      "getHealth",
			handler: healthz,
			status:  http.StatusNoContent,
			public:  true,
		},
		{
			method:  http.MethodGet,
			path:    "/readyz",
			id:      "getReady",
			handler: s.readyz,
			status:  http.StatusOK,
			more:    []int{http.StatusServiceUnavailable},
			public:  true,
		},
		{
			method:   http.MethodGet,
			path:     "/openapi.yaml",
			id:       "getOpenAPI",
			handler:  s.openAPI,
			status:   http.StatusOK,
			response: new(string),
			public:   true,
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
			method:  http.MethodPost,
			path:    "/logout",
			id:      "logout",
			handler: s.logout,
			status:  http.StatusNoContent,
			public:  true,
		},
		{
			method:  http.MethodPost,
			path:    "/logout/everywhere",
			id:      "logoutEverywhere",
			handler: s.logoutEverywhere,
			status:  http.StatusNoContent,
			errors:  []int{http.StatusUnauthorized},
			public:  true,
		},
	}
}

func addOperation(reflector *openapi3.Reflector, rt route) error {
	oc, err := reflector.NewOperationContext(rt.method, rt.path)
	if err != nil {
		return fmt.Errorf("api: openapi: %w", err)
	}
	oc.SetID(rt.id)
	if rt.request != nil {
		oc.AddReqStructure(rt.request)
	}
	if rt.response != nil || rt.status != 0 {
		oc.AddRespStructure(rt.response, openapi.WithHTTPStatus(rt.status))
	}
	for _, status := range rt.more {
		oc.AddRespStructure(nil, openapi.WithHTTPStatus(status))
	}
	if !rt.public {
		oc.AddSecurity("bearerAuth")
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
