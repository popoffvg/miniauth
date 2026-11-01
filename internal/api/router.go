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
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/oauth"
	"github.com/popoffvg/miniauth/internal/providers/google"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/providers/telegram"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/useradmin"
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
	passwords   *password.Service
	recovery    *recovery.Service
	google      *google.Step
	telegram    *telegram.Step
	links       *identitylink.Service
	passkeys    *passkey.Service
	totp        *totp.Service
	spec        []byte

	// invites is nil unless WithInvites sets it.
	invites *invites.Service
	// userAdmin is nil unless WithUserAdmin sets it.
	userAdmin *useradmin.Service
	// groupAdmin is nil unless WithGroupAdmin sets it.
	groupAdmin *groupadmin.Service
	// oauth and oauthResources are nil unless WithOAuth sets them.
	oauth          *oauth.Service
	oauthResources resourceDirectory
}

// WithLogin serves the login page. Without it, the login routes answer 503.
func WithLogin(flows *loginflow.LoginFlows, passwords *password.Service) RouterOption {
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
			path:     "/api/v1/users",
			id:       "listUsers",
			handler:  s.listUsers,
			response: new(userListBody),
			status:   http.StatusOK,
			errors:   []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
			doc:      "Lists every user in login order, with the groups, the state, the device count, and the last time a device was seen.",
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/users/{login}/disable",
			id:      "disableUser",
			handler: s.disableUserAPI,
			request: new(userLoginPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
			doc:     "Disables the user and deletes every session of the user in one transaction. The next /auth/check of the user is refused. A disabled user stays disabled. A change of the same user at the same moment is 409.",
		},
		{
			method:  http.MethodPost,
			path:    "/api/v1/users/{login}/enable",
			id:      "enableUser",
			handler: s.enableUserAPI,
			request: new(userLoginPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
			doc:     "Enables the user. The user signs in again; no session comes back. A change of the same user at the same moment is 409.",
		},
		{
			method:  http.MethodPut,
			path:    "/api/v1/groups/{group}/members/{login}",
			id:      "addGroupMember",
			handler: s.addMemberAPI,
			request: new(groupMemberPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:     "Adds the user to the group. A member stays a member: the request is idempotent. An unknown user or group is 404.",
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/groups/{group}/members/{login}",
			id:      "removeGroupMember",
			handler: s.removeMemberAPI,
			request: new(groupMemberPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:     "Removes the user from the group. A user who is not in the group is 404.",
		},
		{
			method:   http.MethodGet,
			path:     "/api/v1/groups",
			id:       "listGroups",
			handler:  s.listGroups,
			response: new(groupListBody),
			status:   http.StatusOK,
			errors:   []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
			doc:      "Lists every group in name order, with its member count and its resources. A group reaches a resource through a group grant.",
		},
		{
			method:   http.MethodPost,
			path:     "/api/v1/groups",
			id:       "createGroup",
			handler:  s.createGroup,
			request:  new(createGroupRequest),
			response: new(groupBody),
			status:   http.StatusCreated,
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusConflict,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
				http.StatusServiceUnavailable,
			},
			doc: "Creates an empty group. A name that is stored is 409.",
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/groups/{group}",
			id:      "deleteGroup",
			handler: s.deleteGroup,
			request: new(groupPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
			doc:     "Deletes the group, its memberships, and its grants. The built-in groups admins and users are 409. A group that MINIAUTH_RESOURCES_FILE names is 409.",
		},
		{
			method:  http.MethodPut,
			path:    "/api/v1/groups/{group}/resources/{name}",
			id:      "addGroupResource",
			handler: s.addGroupResource,
			request: new(groupResourcePath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:     "Gives the group the resource: a group grant with no expiry. A group with an active grant keeps it: the request is idempotent. An expired grant is replaced by one with no expiry. An unknown group or resource is 404.",
		},
		{
			method:  http.MethodDelete,
			path:    "/api/v1/groups/{group}/resources/{name}",
			id:      "removeGroupResource",
			handler: s.removeGroupResource,
			request: new(groupResourcePath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
			doc:     "Revokes the grant of the resource to the group. A group without the resource is 404. A grant from MINIAUTH_RESOURCES_FILE is 409.",
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
			errors:  []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
			doc:     "Deletes the resource and its grants. A resource from MINIAUTH_RESOURCES_FILE is 409.",
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
			doc: "Gives one user or one group one resource. The body names exactly one of user (a login) and group. expires_at is RFC 3339 and MUST be in the future; with no expires_at the grant does not expire. An unknown user, group, or resource is 404. A grant that already exists is 409.",
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
			errors:  []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
			doc:     "Revokes the grant. The next /auth/check does not count it. A grant from MINIAUTH_RESOURCES_FILE is 409.",
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
			doc: "Creates an invite to one group; with no group it is users. The reply holds the one-time link {public URL}/invite/{token}, shown once: only the SHA-256 of the token is stored. The link expires after 7 days. An unknown group is 404. Without MINIAUTH_PUBLIC_URL it is 503.",
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
			doc:      "Accepts the invite in the form. Origin MUST be the public origin, else 403. In one transaction it marks the invite used and creates the user with a password identity in the group of the invite and in users. Then it starts a session and redirects to the overview page. A taken login shows the form again with 409, and the invite stays unused. An unknown, used, or expired token is 410.",
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
			method:   http.MethodGet,
			path:     TelegramCallbackPath,
			id:       "telegramCallback",
			handler:  s.telegramCallback,
			request:  new(telegramCallbackRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusBadRequest, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "The data-auth-url of the Telegram Login Widget. It needs the login flow cookie of an open flow, and flow_nonce MUST be the nonce of that flow, so data sent to another browser is 400. The hash MUST be the HMAC-SHA256 of the other fields, sorted by key and joined as key=value lines, keyed with the SHA-256 of the bot token. Data older than one day, more than a minute in the future, or used before is 400. Only the id field links the account. A linked account completes the flow: it sets the session cookie and redirects to the return URL. An unknown account starts no session and creates no user: it is kept 15 minutes as a pending link bound to the browser by the cookie __Host-id_pending_link, and the page asks for a password login, which then links it.",
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
			path:        passkeyScriptPath,
			id:          "passkeyScript",
			handler:     servePasskeyScript,
			response:    new(string),
			status:      http.StatusOK,
			contentType: "text/javascript",
			doc:         "The one script of the service. It runs the WebAuthn ceremonies of the login page and of the page that adds a passkey.",
			isPublic:    true,
		},
		{
			method:      http.MethodGet,
			path:        appCSSPath,
			id:          "appStylesheet",
			handler:     serveAppCSS,
			response:    new(string),
			status:      http.StatusOK,
			contentType: "text/css",
			doc:         "The one stylesheet of every page.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     passkeyLoginPath + "/options",
			id:       "passkeyLoginOptions",
			handler:  s.passkeyLoginOptions,
			response: new(passkeyOptions),
			status:   http.StatusOK,
			errors:   []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Stores a new WebAuthn challenge on the login flow in the flow cookie and returns the options for navigator.credentials.get. The options require user verification and name no credential. Origin MUST be the public origin, else 403.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     passkeyLoginPath,
			id:       "passkeyLogin",
			handler:  s.passkeyLogin,
			request:  new(passkeyCredential),
			response: new(passkeyDone),
			status:   http.StatusOK,
			errors:   []int{http.StatusBadRequest, http.StatusForbidden, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Checks the assertion against the challenge of the login flow. The challenge is cleared before the check, so it is used once. A passkey with user verification counts as two factors: it completes the flow alone, sets the session cookie, and answers the return URL. A response without user verification, an unknown credential, or a signature counter that does not increase is 400. Origin MUST be the public origin, else 403.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        passkeyNewPath,
			id:          "passkeyNewPage",
			handler:     s.passkeyNewPage,
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "The form that adds a passkey for the session user. With no session it redirects to the login page. A login older than 10 minutes shows the step-up password form first, which returns here.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     passkeysPath + "/options",
			id:       "passkeyAddOptions",
			handler:  s.passkeyAddOptions,
			response: new(passkeyOptions),
			status:   http.StatusOK,
			errors:   []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Starts a flow of the session user with a new WebAuthn challenge, sets the flow cookie, and returns the options for navigator.credentials.create. The options require a discoverable credential and user verification. A login older than 10 minutes is 403. Origin MUST be the public origin, else 403.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     passkeysPath,
			id:       "passkeyAdd",
			handler:  s.passkeyAdd,
			request:  new(passkeyAddRequest),
			response: new(passkeyDone),
			status:   http.StatusCreated,
			errors:   []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Checks the new credential against the challenge of the flow in the flow cookie and stores the passkey. The challenge is used once. A credential without user verification is 400. A credential that is already stored is 409. A login older than 10 minutes is 403. Origin MUST be the public origin, else 403.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     passkeysPath + "/{id}/delete",
			id:       "deletePasskey",
			handler:  s.deletePasskey,
			request:  new(passkeyDeleteRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Deletes one passkey of the session user and redirects to GET /sessions?done=passkey-deleted. Origin MUST be the public origin, else 403. A login older than 10 minutes shows the step-up password form instead, which returns to the sessions page. A passkey of another user is 404.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        loginTOTPPath,
			id:          "loginTOTPPage",
			handler:     s.stepPage(loginflow.FactorTOTP),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Shows the TOTP form of the flow in the login flow cookie, after the password of a user with two-step login. When the step is not open, it shows the open steps.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     loginTOTPPath,
			id:       "loginTOTP",
			handler:  s.loginTOTP,
			request:  new(codeFormRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Checks a TOTP code for the user of the flow in the login flow cookie. Origin MUST be the public origin, else 403. A code is accepted once. A complete flow sets the session cookie and redirects to the return URL. A wrong or used code shows the form again with 200. A backoff is 429.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        loginRecoveryCodePath,
			id:          "loginRecoveryCodePage",
			handler:     s.stepPage(loginflow.FactorRecovery),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			pages:       []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Shows the recovery code form of the flow in the login flow cookie. A recovery code replaces the TOTP code once.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     loginRecoveryCodePath,
			id:       "loginRecoveryCode",
			handler:  s.loginRecoveryCode,
			request:  new(recoveryFormRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Spends one recovery code of the user of the flow in the login flow cookie, in place of a TOTP code. Origin MUST be the public origin, else 403. A used code shows the form again with 200. A backoff is 429, shared with the TOTP step.",
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
			doc:         "The overview page, the default page after a login: the login, the groups, the two-step login state, and the counts of active tokens, devices, and passkeys. With no session it redirects to the login page.",
			isPublic:    true,
		},
		{
			method:      http.MethodGet,
			path:        tokensPath,
			id:          "tokenPage",
			handler:     s.tokenPage,
			request:     new(tokenPageRequest),
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
			doc:      "Revokes one token of the session user and redirects to GET /tokens?done=token-revoked. Origin MUST be the public origin, else 403. A token of another user is 404.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     consentsPath + "/{id}/revoke",
			id:       "revokeConsent",
			handler:  s.revokeConsent,
			request:  new(consentRevokeRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Disconnects one app of the session user. It revokes the consent and deletes its tokens. It redirects to GET /tokens?done=app-revoked. The next connection shows the consent page again. Origin MUST be the public origin, else 403. A consent of another user is 404.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     oauthClientsPath,
			id:       "createOAuthClient",
			handler:  s.createOAuthClient,
			request:  new(createOAuthClientRequest),
			response: new(oauthClientBody),
			status:   http.StatusCreated,
			errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusRequestEntityTooLarge,
				http.StatusUnsupportedMediaType,
				http.StatusServiceUnavailable,
			},
			doc: "Registers an MCP client for the OAuth sign-in. The client is public: it gets a client_id and no secret, and proves each code exchange with PKCE. Each redirect URI is https, or http on a loopback host; a loopback URI matches on any port.",
		},
		{
			method:   http.MethodGet,
			path:     oauthClientsPath,
			id:       "listOAuthClients",
			handler:  s.listOAuthClients,
			response: new(oauthClientList),
			status:   http.StatusOK,
			errors:   []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
			doc:      "Lists every OAuth client, oldest first.",
		},
		{
			method:  http.MethodDelete,
			path:    oauthClientsPath + "/{id}",
			id:      "deleteOAuthClient",
			handler: s.deleteOAuthClient,
			request: new(oauthClientPath),
			status:  http.StatusNoContent,
			errors:  []int{http.StatusUnauthorized, http.StatusNotFound, http.StatusServiceUnavailable},
			doc:     "Deletes the client, its consents, and every token it got. The next /auth/check refuses its tokens.",
		},
		{
			method:   http.MethodGet,
			path:     authorizationServerMetadataPath,
			id:       "authorizationServerMetadata",
			handler:  s.serveAuthorizationServerMetadata,
			response: new(authorizationServerMetadata),
			status:   http.StatusOK,
			errors:   []int{http.StatusServiceUnavailable},
			doc:      "The RFC 8414 metadata of the OAuth server. The issuer is MINIAUTH_PUBLIC_URL. Without OAuth or a public URL it is 503.",
			isPublic: true,
		},
		{
			method:   http.MethodGet,
			path:     protectedResourceMetadataPath,
			id:       "protectedResourceMetadataRoot",
			handler:  s.serveProtectedResourceMetadata,
			response: new(protectedResourceMetadata),
			status:   http.StatusOK,
			errors:   []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "The RFC 9728 metadata of the resource with the path prefix / on X-Forwarded-Host. The reverse proxy sends this path of each MCP host here, with no forward-auth. A URL that is not exactly a resource is 404.",
			isPublic: true,
		},
		{
			method:   http.MethodGet,
			path:     protectedResourceMetadataPath + "/{path...}",
			id:       "protectedResourceMetadata",
			handler:  s.serveProtectedResourceMetadata,
			request:  new(protectedResourcePath),
			response: new(protectedResourceMetadata),
			status:   http.StatusOK,
			errors:   []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "The RFC 9728 metadata of the resource with this path prefix on X-Forwarded-Host. A URL that is not exactly a resource is 404.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        oauthAuthorizePath,
			id:          "oauthAuthorize",
			handler:     s.authorizePage,
			request:     new(authorizeRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusFound, http.StatusSeeOther},
			pages:       []int{http.StatusBadRequest, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "The OAuth authorization endpoint. An unknown client_id or an unregistered redirect_uri is a 400 page: nothing goes to that URI. Any other refusal redirects to the client with error and state. With no session it sends the browser to the login page first. A client the user approved before for the resource gets a code at once with 302.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     oauthAuthorizePath,
			id:       "oauthConsent",
			handler:  s.answerConsent,
			request:  new(authorizeRequest),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "The consent form. Origin MUST be the public origin, else 403. It checks every field again. action=allow records the consent and redirects to the client with a code, iss, and state. action=deny redirects with error=access_denied.",
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     oauthTokenPath,
			id:       "oauthToken",
			handler:  s.exchangeToken,
			request:  new(tokenRequest),
			response: new(tokenResponse),
			status:   http.StatusOK,
			doc:      "The OAuth token endpoint, for a public client. A code spends once, and client_id, redirect_uri, and code_verifier MUST match the authorization request. A refresh rotates the refresh token. A code or refresh token sent twice ends the consent and all its tokens. The access token is an idp_ token for one resource for one hour. Errors are RFC 6749 JSON.",
			isPublic: true,
		},
		{
			method:      http.MethodGet,
			path:        linkPagePath,
			id:          "linkPage",
			handler:     s.linkPage,
			request:     new(linkPageRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusFound, http.StatusSeeOther},
			pages:       []int{http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Names the Google or Telegram account of the pending link cookie and asks the session user to link it or not. A password login in a browser with a pending link redirects here; it never links by itself. With no live pending link, or a session without a password, it redirects with 302 to the return URL. With no session it redirects to the login page.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     linkPagePath,
			id:       "confirmLink",
			handler:  s.confirmLink,
			request:  new(linkForm),
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusBadRequest, http.StatusForbidden, http.StatusConflict, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Links (action=link) or deletes (action=skip) the pending link of this browser, then redirects to the return URL. Origin MUST be the public origin, else 403. An account linked to another user is 409. A store error is 500 and keeps the pending link cookie, so the form can be sent again.",
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
			doc:         "Lists the resources and their grants, with the forms to change them. Only a member of the group admins opens it; any other user is 403. With no session it redirects to the login page, which returns here.",
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
			method:      http.MethodGet,
			path:        usersPagePath,
			id:          "usersPage",
			handler:     s.usersPage,
			request:     new(usersPageRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Lists the users with their groups and state, with the forms to change them and to make an invite link. Only a member of the group admins opens it; any other user is 403. With no session it redirects to the login page, which returns here.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     usersPagePath + "/{login}/disable",
			id:       "disableUserForm",
			handler:  s.disableUserForm,
			request:  new(userLoginPath),
			status:   http.StatusSeeOther,
			pages:    usersFormPages,
			doc:      "Disables the user, deletes every session of the user, and redirects to GET /users?done=user-disabled. An admin cannot disable itself: 409. " + usersFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     usersPagePath + "/{login}/enable",
			id:       "enableUserForm",
			handler:  s.enableUserForm,
			request:  new(userLoginPath),
			status:   http.StatusSeeOther,
			pages:    usersFormPages,
			doc:      "Enables the user and redirects to GET /users?done=user-enabled. " + usersFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     usersPagePath + "/{login}/groups",
			id:       "addMemberForm",
			handler:  s.addMemberForm,
			request:  new(userGroupForm),
			status:   http.StatusSeeOther,
			pages:    usersFormPages,
			doc:      "Adds the user to the group of the form and redirects to GET /users?done=member-added. An unknown group is 404. " + usersFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     usersPagePath + "/{login}/groups/{group}/remove",
			id:       "removeMemberForm",
			handler:  s.removeMemberForm,
			request:  new(groupMemberPath),
			status:   http.StatusSeeOther,
			pages:    usersFormPages,
			doc:      "Removes the user from the group and redirects to GET /users?done=member-removed. An admin cannot leave the group admins: 409. " + usersFormDoc,
			isPublic: true,
		},
		{
			method:      http.MethodPost,
			path:        usersPagePath + "/invites",
			id:          "makeInviteForm",
			handler:     s.makeInviteForm,
			request:     new(userInviteForm),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Makes an invite link to the group of the form and shows it once, with Cache-Control: no-store. An empty group is users. " + usersFormDoc,
			isPublic:    true,
		},
		{
			method:      http.MethodGet,
			path:        groupsPagePath,
			id:          "groupsPage",
			handler:     s.groupsPage,
			request:     new(groupsPageRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Lists the groups with their member counts and resources, with the forms to change them. Only a member of the group admins opens it; any other user is 403. With no session it redirects to the login page, which returns here.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     groupsPagePath,
			id:       "createGroupForm",
			handler:  s.createGroupForm,
			request:  new(groupForm),
			status:   http.StatusSeeOther,
			pages:    groupsFormPages,
			doc:      "Creates an empty group and redirects to GET /groups?done=group-created. " + groupsFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     groupsPagePath + "/{group}/delete",
			id:       "deleteGroupForm",
			handler:  s.deleteGroupForm,
			request:  new(groupPath),
			status:   http.StatusSeeOther,
			pages:    groupsFormPages,
			doc:      "Deletes the group, its memberships, and its grants, and redirects to GET /groups?done=group-deleted. A built-in group or a group from the resources file is 409. " + groupsFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     groupsPagePath + "/{group}/resources",
			id:       "addGroupResourceForm",
			handler:  s.addGroupResourceForm,
			request:  new(groupResourceForm),
			status:   http.StatusSeeOther,
			pages:    groupsFormPages,
			doc:      "Gives the group the resource of the form and redirects to GET /groups?done=group-resource-added. " + groupsFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     groupsPagePath + "/{group}/resources/{name}/remove",
			id:       "removeGroupResourceForm",
			handler:  s.removeGroupResourceForm,
			request:  new(groupResourcePath),
			status:   http.StatusSeeOther,
			pages:    groupsFormPages,
			doc:      "Revokes the grant of the resource to the group and redirects to GET /groups?done=group-resource-removed. A grant from the resources file is 409. " + groupsFormDoc,
			isPublic: true,
		},
		{
			method:   http.MethodPost,
			path:     "/logout",
			id:       "logout",
			handler:  s.logout,
			status:   http.StatusNoContent,
			empty:    []int{http.StatusSeeOther},
			doc:      "Deletes the sessions of the request. A browser form is redirected to the login page with 303; any other client gets 204.",
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
			request:     new(sessionsPageRequest),
			response:    new(string),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusFound},
			errors:      []int{http.StatusUnauthorized},
			doc:         "The security page: the devices, the passkeys, and the two-step login state of the session user. A browser with no session is redirected to the login page. Any other request with no session is 401.",
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
			doc:      "Deletes the session of a device of the session user. The device stays. Origin MUST be the public URL origin, else 403. Redirects to GET /sessions?done=signed-out.",
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
			doc:      "Deletes a device of the session user and its session. Origin MUST be the public URL origin, else 403. Redirects to GET /sessions?done=forgotten.",
			isPublic: true,
		},
		{
			method:      http.MethodPost,
			path:        totpEnrollPath,
			id:          "enrollTOTP",
			handler:     s.enrollTOTP,
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Makes a TOTP secret for the session user and shows it once as a QR code and as base32 text, with Cache-Control: no-store. Origin MUST be the public origin, else 403. A login older than 10 minutes starts a step-up first: the page asks for the password and returns to GET /sessions. Without MINIAUTH_TOTP_KEY it is 503.",
			isPublic:    true,
		},
		{
			method:      http.MethodPost,
			path:        totpConfirmPath,
			id:          "confirmTOTP",
			handler:     s.confirmTOTP,
			request:     new(codeFormRequest),
			response:    new(htmlPage),
			status:      http.StatusOK,
			contentType: "text/html",
			empty:       []int{http.StatusSeeOther},
			pages:       []int{http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:         "Turns on two-step login when the code matches the new secret, and shows 10 recovery codes once, with Cache-Control: no-store. A wrong code shows the secret again with 200. A setup older than 15 minutes is 400.",
			isPublic:    true,
		},
		{
			method:   http.MethodPost,
			path:     totpDisablePath,
			id:       "disableTOTP",
			handler:  s.disableTOTP,
			status:   http.StatusSeeOther,
			pages:    []int{http.StatusOK, http.StatusBadRequest, http.StatusForbidden, http.StatusInternalServerError, http.StatusServiceUnavailable},
			doc:      "Turns off two-step login and deletes the recovery codes, then redirects to GET /sessions?done=two-step-off. Origin MUST be the public origin, else 403. A login older than 10 minutes starts a step-up first.",
			isPublic: true,
		},
	}
}

func addOperation(reflector *openapi3.Reflector, rt route) error {
	// The mux suffix {$} matches only the exact path, and {name...} matches the rest of the path.
	// OpenAPI has neither syntax.
	specPath := strings.ReplaceAll(strings.TrimSuffix(rt.path, "{$}"), "...}", "}")
	oc, err := reflector.NewOperationContext(rt.method, specPath)
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
