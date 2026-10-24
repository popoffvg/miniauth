package api

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"

	"github.com/popoffvg/miniauth/internal/user"
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
}

type service struct {
	users *user.Users
	admin AdminTokenHash
	spec  []byte
}

// NewRouter serves the HTTP API.
// admin is the SHA-256 of the bootstrap token.
func NewRouter(users *user.Users, admin AdminTokenHash, logger *slog.Logger) (http.Handler, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	svc := &service{users: users, admin: admin}
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

func (s *service) openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.spec)
}
