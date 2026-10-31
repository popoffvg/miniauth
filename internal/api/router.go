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

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/googlestep"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// route is one HTTP operation.
// isPublic is false unless the row sets it, so a new row is authenticated.
// repeated lists more success statuses that send the response body.
type route struct {
	method   string
	path     string
	id       string
	handler  http.HandlerFunc
	request  any
	response any
	status   int
	repeated []int
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
	accounts *users.Service
	browser  *sessions.Service
	groups   groupList
	grants   urlAccess
	// accessAdmin is nil unless WithAccessAdmin sets it.
	accessAdmin *access.Service
	domain      sessions.Domain
	publicURL   PublicURL
	admin       AdminTokenHash
	tokens      *tokens.Service
	ready       Readiness
	flows       *loginflow.LoginFlows
	passwords   *passwordstep.Service
	recovery    *recovery.Service
	google      *googlestep.Step
	links       *identitylink.Service
	spec        []byte

	// invites is nil unless WithInvites sets it.
	invites *invites.Service
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
			method:   http.MethodPost,
			path:     "/api/v1/tokens/import",
			id:       "importToken",
			handler:  s.importToken,
			request:  new(importTokenRequest),
			response: new(importedToken),
			status:   http.StatusCreated,
			repeated: []int{http.StatusOK},
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusNotFound,
				http.StatusConflict,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
			},
			doc: "Stores the SHA-256 of a token made outside miniauth, so a client keeps its token. The token does not expire. 201 stores the token. 200 means the user already has the token: nothing changes. 409 means another user has the token. 404 means the login is not known.",
		},
		{
			method:   http.MethodPost,
			path:     "/api/v1/resources",
			id:       "createResource",
			handler:  s.createResource,
			request:  new(createResourceRequest),
			response: new(resourceBody),
			status:   http.StatusCreated,
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusConflict,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
				http.StatusServiceUnavailable,
			},
			doc: "Creates a resource that /auth/check protects. url MUST be an absolute http or https URL with no query. Only the host and the path are stored, and a reply url is the host and the path with no scheme. A name, or a host and path, that is already stored is 409.",
		},
		{
			method:   http.MethodGet,
			path:     "/api/v1/resources",
			id:       "listResources",
			handler:  s.listResources,
			response: new(resourceList),
			status:   http.StatusOK,
			errors:   []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
			doc:      "Lists every resource in name order.",
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/resources/{name}",
			id:      "deleteResource",
			handler: s.deleteResource,
			request: new(resourcePath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:     "Deletes the resource and its grants.",
		},
		{
			method:   http.MethodPost,
			path:     "/api/v1/grants",
			id:       "createGrant",
			handler:  s.createGrant,
			request:  new(createGrantRequest),
			response: new(grantBody),
			status:   http.StatusCreated,
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusNotFound,
				http.StatusConflict,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
				http.StatusServiceUnavailable,
			},
			doc: "Gives one user or one group one resource. The body names exactly one of user (a login) and group. expires_at is RFC 3339 and MUST be in the future; with no expires_at the grant does not expire. An unknown user or resource is 404. A grant that already exists is 409.",
		},
		{
			method:   http.MethodGet,
			path:     "/api/v1/grants",
			id:       "listGrants",
			handler:  s.listGrants,
			request:  new(listGrantsRequest),
			response: new(grantList),
			status:   http.StatusOK,
			errors:   []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:      "Lists the grants, expired ones too, in resource name order. Each grant names its resource, its user or group, its expiry, and its creation time. user selects the grants to that user, not the grants to the user's groups. resource selects the grants of that resource. An unknown user or resource in the query is 404.",
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/grants/{id}",
			id:      "revokeGrant",
			handler: s.revokeGrant,
			request: new(grantPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:     "Revokes the grant. The next /auth/check does not count it.",
		},
		{
			method:   http.MethodPost,
			path:     "/api/v1/invites",
			id:       "createInvite",
			handler:  s.createInvite,
			request:  new(createInviteRequest),
			response: new(inviteBody),
			status:   http.StatusCreated,
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusNotFound,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
				http.StatusServiceUnavailable,
			},
			doc: "Creates an invite for one resource. The reply holds the one-time link {public URL}/invite/{token}, shown once: only the SHA-256 of the token is stored. The link expires after 7 days. An unknown resource is 404.",
		},
		{
			method:      http.MethodGet,
			path:        "/invite/{token}",
			id:          "invitePage",
			handler:     s.invitePage,
			request:     new(invitePath),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusGone, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Shows the account form of an open invite. An unknown, used, or expired token is 410 with one page for the three cases. The request log shows the route pattern, not the token.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     "/invite/accept",
			id:       "acceptInvite",
			handler:  s.acceptInvite,
			request:  new(inviteFormRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusGone, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Accepts the invite in the form. Origin MUST be the public origin, else 403. In one transaction it marks the invite used, creates the user with a password identity, and grants the resource. Then it starts a session and redirects to https, the host, and the path prefix of the resource. A taken login shows the form again with 409, and the invite stays unused. An unknown, used, or expired token is 410.",
			isPublic: true,
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
			doc:      "Checks the password for the flow in the login flow cookie. Origin MUST be the public origin, else 403. A complete flow sets the session cookie and redirects to the return URL. A wrong login or password shows the form again with 200. A backoff is 429. A step-up flow reads only the password, checks it for the user of the flow, renews the auth time of the session, and redirects to the return URL.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     googleLoginPath,
			id:       "googleLogin",
			handler:  s.googleLogin,
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Starts the Google step for the flow in the login flow cookie and redirects to Google with PKCE. Origin MUST be the public origin, else 403. The PKCE verifier goes to the HttpOnly cookie __Host-id_google_verifier. Without Google config, or while Google discovery fails, it is 503.",
			isPublic: true,
		},
		{
			method:   http.MethodGet,
			path:     GoogleCallbackPath,
			id:       "googleCallback",
			handler:  s.googleCallback,
			request:  new(googleCallbackRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusBadRequest, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Checks the Google reply: state, PKCE verifier, ID token issuer, audience, expiry, and nonce. Only the sub claim links the account. A linked account completes the flow: it sets the session cookie and redirects to the return URL. An unknown account starts no session and creates no user: it is kept 15 minutes as a pending link bound to the browser by the cookie __Host-id_pending_link, and the page asks for a password login, which then links it. A bad state, verifier, or token is 400.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        recoverPath,
			id:          "recoverPage",
			handler:     s.recoverPage,
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusServiceUnavailable},
			doc:         "Asks for the email address of a user who forgot the password. 503 when no mail sender is configured.",
			isPublic:    true,
		},
		{
			method:      http.MethodPost,
			path:        recoverPath,
			id:          "recover",
			handler:     s.requestRecovery,
			request:     new(recoverFormRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Sends a one-time reset link to the login equal to the email, in the background. A known and an unknown address get the same 200 page. Origin MUST be the public origin, else 403. A backoff per address and per client IP is 429.",
			isPublic:    true,
		},
		{
			method:      http.MethodGet,
			path:        resetLinkPattern,
			id:          "resetPage",
			handler:     s.resetPage,
			request:     new(resetPageRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "The link from the recovery mail. It shows the new password form with the token in a hidden field. Referrer-Policy is no-referrer. An unknown, used, or expired link is 400.",
			isPublic:    true,
		},
		{
			method:      http.MethodPost,
			path:        resetFormPath,
			id:          "resetPassword",
			handler:     s.reset,
			request:     new(resetFormRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Sets the new password through the token in the form. Every session of the user is deleted. Personal access tokens stay valid. The link cannot be used again. Origin MUST be the public origin, else 403.",
			isPublic:    true,
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
			method:      http.MethodGet,
			path:        tokensPath,
			id:          "tokenPage",
			handler:     s.tokenPage,
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Lists the personal access tokens of the session user, with the form to make one. With no session it redirects to the login page, which returns here.",
			isPublic:    true,
		},
		{
			method:      http.MethodPost,
			path:        tokensPath,
			id:          "createToken",
			handler:     s.createToken,
			request:     new(tokenFormRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Makes a personal access token and shows it once, with Cache-Control: no-store. Origin MUST be the public origin, else 403. A login older than 10 minutes starts a step-up instead: the page asks for the password of the session user and returns to GET /tokens.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     tokensPath + "/{id}/revoke",
			id:       "revokeToken",
			handler:  s.revokeToken,
			request:  new(tokenRevokeRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Revokes one token of the session user and redirects to GET /tokens. Origin MUST be the public origin, else 403. A token of another user is 404.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        accessPagePath,
			id:          "accessPage",
			handler:     s.accessPage,
			request:     new(accessPageRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Lists the resources and their grants, with the forms to change them. Only a member of the group admin opens it; any other user is 403. With no session it redirects to the login page, which returns here.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     accessPagePath + "/resources",
			id:       "addResourceForm",
			handler:  s.addResourceForm,
			request:  new(accessResourceForm),
			status:   http.StatusSeeOther,
			pages:    accessFormPages,
			doc:      "Adds a resource through the access service and redirects to GET /access?done=resource-added. " + accessFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     accessPagePath + "/resources/{name}/delete",
			id:       "deleteResourceForm",
			handler:  s.deleteResourceForm,
			request:  new(accessResourcePath),
			status:   http.StatusSeeOther,
			pages:    accessFormPages,
			doc:      "Deletes a resource and its grants and redirects to GET /access?done=resource-deleted. " + accessFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     accessPagePath + "/grants",
			id:       "grantForm",
			handler:  s.grantForm,
			request:  new(accessGrantForm),
			status:   http.StatusSeeOther,
			pages:    accessFormPages,
			doc:      "Gives one user or one group a resource and redirects to GET /access?done=granted. " + accessFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     accessPagePath + "/grants/{id}/revoke",
			id:       "revokeForm",
			handler:  s.revokeForm,
			request:  new(accessGrantPath),
			status:   http.StatusSeeOther,
			pages:    accessFormPages,
			doc:      "Revokes a grant and redirects to GET /access?done=revoked. The next /auth/check does not count it. " + accessFormDoc,
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
	for _, status := range rt.repeated {
		oc.AddRespStructure(rt.response, openapi.WithHTTPStatus(status))
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
