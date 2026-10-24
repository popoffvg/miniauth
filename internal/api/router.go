package api

import (
	"log/slog"
	"net/http"

	"github.com/popoffvg/miniauth/internal/user"
)

// Router is the HTTP service.
// Every route is registered in NewRouter.
// The OpenAPI test reads those routes from the mux.
type Router struct {
	mux   *http.ServeMux
	users *user.Users
	admin AdminTokenHash
	log   *slog.Logger
}

// NewRouter serves GET /healthz and POST /api/v1/users.
// admin is the SHA-256 of the bootstrap token.
func NewRouter(users *user.Users, admin AdminTokenHash, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	router := &Router{
		mux:   http.NewServeMux(),
		users: users,
		admin: admin,
		log:   logger,
	}
	router.mux.HandleFunc("GET /healthz", router.healthz)
	router.mux.HandleFunc("POST /api/v1/users", router.createUser)
	return router
}

// ServeHTTP dispatches the request.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *Router) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
