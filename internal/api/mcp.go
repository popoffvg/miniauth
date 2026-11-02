package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	mcpPath = "/mcp"
	// mintedTokenLifetime is how long a token from the mint_token tool works.
	mintedTokenLifetime = 10 * time.Minute
	// maxMintedScopes keeps one tool call to a short list of URL prefixes.
	maxMintedScopes   = 16
	mintedTokenPrefix = "mcp: "
)

// toolRefusal is the text an MCP tool error shows to the agent. It names no secret and no internal error.
type toolRefusal string

func (t toolRefusal) Error() string { return string(t) }

const (
	errMintNoScope    toolRefusal = "Name at least one URL prefix in scopes."
	errMintManyScopes toolRefusal = "Name at most 16 URL prefixes in scopes."
	errMintScope      toolRefusal = "Each scope must be an http or https URL prefix with no query."
	errMintOwnHost    toolRefusal = "A minted token cannot reach the identity server."
	errMintNoGrant    toolRefusal = "Each scope must be under a resource that you have a grant on. Call list_resources."
	errMintName       toolRefusal = "The name must have 1 to 59 characters."
	errMintFailed     toolRefusal = "The token operation failed. Try again."
)

var errMCPCallerMissing = errors.New("api: mcp caller is missing")

// mcpCaller is the user that a bearer token on POST /mcp authenticated.
type mcpCaller struct {
	user   users.User
	groups []groups.Name
}

type mcpCallerKey struct{}

// mintTokenInput is the input of the mint_token tool.
type mintTokenInput struct {
	Scopes []string `json:"scopes" jsonschema:"URL prefixes the token reaches, for example https://app.example.test/api/. Each MUST be under a resource that you have a grant on."`
	Name   string   `json:"name,omitempty" jsonschema:"A name you know the token by on the Tokens page. The page shows it after 'mcp: '."`
}

// mintTokenOutput is the output of the mint_token tool. Token is the secret; it is in this reply only.
type mintTokenOutput struct {
	Token     string    `json:"token" jsonschema:"Send it as Authorization: Bearer <token>."`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    []string  `json:"scopes"`
}

type listResourcesInput struct{}

type listResourcesOutput struct {
	Resources []mcpResource `json:"resources"`
}

type mcpResource struct {
	Name string `json:"name"`
	URL  string `json:"url" jsonschema:"A URL prefix that mint_token accepts as a scope."`
}

// newMCPHandler serves the MCP tools. serveMCP authenticates the caller before this handler runs.
func (s *service) newMCPHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "miniauth", Version: "0.0.0"}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "mint_token",
		Description: "Makes a personal access token that works for 10 minutes on the URL prefixes in scopes. Use it to call a protected endpoint as the signed-in user.",
	}, s.mintToken)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_resources",
		Description: "Lists the protected URL prefixes that the signed-in user has a grant on. Each URL is a valid scope for mint_token.",
	}, s.listMCPResources)
	streamable := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
	return auth.RequireBearerToken(verifyMCPCaller, nil)(streamable)
}

// verifyMCPCaller passes the caller that serveMCP put in the context to the tool handlers.
func verifyMCPCaller(ctx context.Context, _ string, _ *http.Request) (*auth.TokenInfo, error) {
	caller, ok := ctx.Value(mcpCallerKey{}).(mcpCaller)
	if !ok {
		return nil, errors.Join(auth.ErrInvalidToken, errMCPCallerMissing)
	}
	return &auth.TokenInfo{
		UserID:     caller.user.Login.String(),
		Expiration: time.Now().Add(time.Minute),
		Extra:      map[string]any{"caller": caller},
	}, nil
}

func (s *service) serveMCP(w http.ResponseWriter, r *http.Request) {
	if s.mcp == nil || s.tokens == nil || s.publicURL.Origin() == "" {
		writeProblem(w, http.StatusServiceUnavailable, "The MCP server is not configured.")
		return
	}
	caller, ok := s.authenticateMCP(w, r)
	if !ok {
		return
	}
	s.mcp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mcpCallerKey{}, caller)))
}

// authenticateMCP checks the bearer token like GET /auth/check does for the URL of POST /mcp.
// It returns false after it wrote a reply.
func (s *service) authenticateMCP(w http.ResponseWriter, r *http.Request) (mcpCaller, bool) {
	bearer, ok := accessTokenBearer(r)
	if !ok {
		s.mcpUnauthorized(w, false)
		return mcpCaller{}, false
	}
	secret, err := tokens.ParseSecret(bearer.raw)
	if err != nil {
		s.mcpUnauthorized(w, true)
		return mcpCaller{}, false
	}
	token, err := s.tokens.Authenticate(r.Context(), secret)
	if errors.Is(err, tokens.ErrInvalid) {
		s.mcpUnauthorized(w, true)
		return mcpCaller{}, false
	}
	if err != nil {
		authCheckFailed(w, r, err)
		return mcpCaller{}, false
	}
	user, err := s.accounts.Find(r.Context(), token.UserID)
	if errors.Is(err, users.ErrNotFound) || err == nil && user.Disabled() {
		s.mcpUnauthorized(w, true)
		return mcpCaller{}, false
	}
	if err != nil {
		authCheckFailed(w, r, err)
		return mcpCaller{}, false
	}
	endpoint, err := tokens.ParseTarget(s.publicURL.Origin() + mcpPath)
	if err != nil || !token.Scopes.Covers(endpoint) {
		writeProblem(w, http.StatusForbidden, "The token does not reach "+mcpPath+".")
		return mcpCaller{}, false
	}
	have, err := s.groups.List(r.Context(), user.ID)
	if err != nil {
		authCheckFailed(w, r, err)
		return mcpCaller{}, false
	}
	target, err := requestURLOf(s.publicURL.Origin() + mcpPath)
	if err == nil {
		err = s.grants.Check(r.Context(), user.ID, have, target)
	}
	if errors.Is(err, access.ErrRequestURL) || errors.Is(err, access.ErrNoResource) || errors.Is(err, access.ErrNoGrant) {
		writeProblem(w, http.StatusForbidden, "The user "+user.Login.String()+" has no grant on "+mcpPath+".")
		return mcpCaller{}, false
	}
	if err != nil {
		authCheckFailed(w, r, err)
		return mcpCaller{}, false
	}
	return mcpCaller{user: user, groups: have}, true
}

func (s *service) mcpUnauthorized(w http.ResponseWriter, isInvalidToken bool) {
	challenge := `Bearer resource_metadata="` + s.publicURL.Origin() + protectedResourceMetadataPath + mcpPath + `"`
	if isInvalidToken {
		challenge = `Bearer error="invalid_token", resource_metadata="` + s.publicURL.Origin() + protectedResourceMetadataPath + mcpPath + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.WriteHeader(http.StatusUnauthorized)
}

func (s *service) mintToken(ctx context.Context, req *mcp.CallToolRequest, in mintTokenInput) (*mcp.CallToolResult, mintTokenOutput, error) {
	caller, err := callerOf(req)
	if err != nil {
		return nil, mintTokenOutput{}, err
	}
	scopes, err := s.mintableScopes(ctx, caller, in.Scopes)
	if err != nil {
		return nil, mintTokenOutput{}, err
	}
	label := in.Name
	if label == "" {
		label = "agent"
	}
	name, err := tokens.ParseName(mintedTokenPrefix + label)
	if err != nil {
		return nil, mintTokenOutput{}, errMintName
	}
	expiresAt := time.Now().Add(mintedTokenLifetime)
	secret, token, err := s.tokens.Issue(ctx, caller.user.ID, name, scopes, expiresAt)
	if err != nil {
		loggerFrom(ctx).ErrorContext(ctx, "miniauth: mint token", "err", err)
		return nil, mintTokenOutput{}, errMintFailed
	}
	return nil, mintTokenOutput{Token: secret.Reveal(), ExpiresAt: token.ExpiresAt, Scopes: token.Scopes.Strings()}, nil
}

// mintableScopes refuses an empty list, a scope on the identity server, and a scope under no granted resource.
func (s *service) mintableScopes(ctx context.Context, caller mcpCaller, raw []string) (tokens.Scopes, error) {
	if len(raw) == 0 {
		return nil, errMintNoScope
	}
	if len(raw) > maxMintedScopes {
		return nil, errMintManyScopes
	}
	scopes, err := tokens.ParseScopes(raw)
	if err != nil {
		return nil, errMintScope
	}
	ownHost, err := tokens.ParseScope(s.publicURL.Origin())
	if err != nil {
		return nil, errMintFailed
	}
	for _, scope := range scopes {
		if sameHost(scope, ownHost) {
			return nil, errMintOwnHost
		}
		target, err := requestURLOf(scope.String())
		if err != nil {
			return nil, errMintScope
		}
		err = s.grants.Check(ctx, caller.user.ID, caller.groups, target)
		if errors.Is(err, access.ErrNoResource) || errors.Is(err, access.ErrNoGrant) {
			return nil, errMintNoGrant
		}
		if err != nil {
			loggerFrom(ctx).ErrorContext(ctx, "miniauth: mint token", "err", err)
			return nil, errMintFailed
		}
	}
	return scopes, nil
}

func (s *service) listMCPResources(ctx context.Context, req *mcp.CallToolRequest, _ listResourcesInput) (*mcp.CallToolResult, listResourcesOutput, error) {
	caller, err := callerOf(req)
	if err != nil {
		return nil, listResourcesOutput{}, err
	}
	out := listResourcesOutput{Resources: []mcpResource{}}
	if s.accessAdmin == nil {
		return nil, out, nil
	}
	resources, err := s.accessAdmin.ListResources(ctx)
	if err != nil {
		loggerFrom(ctx).ErrorContext(ctx, "miniauth: list resources", "err", err)
		return nil, listResourcesOutput{}, errMintFailed
	}
	ownHost, err := tokens.ParseScope(s.publicURL.Origin())
	if err != nil {
		return nil, listResourcesOutput{}, errMintFailed
	}
	for _, resource := range resources {
		// A resource URL has no scheme. Every protected host is served over https.
		prefix := "https://" + resource.URL.String()
		scope, err := tokens.ParseScope(prefix)
		if err != nil || sameHost(scope, ownHost) {
			continue
		}
		target, err := requestURLOf(prefix)
		if err != nil || s.grants.Check(ctx, caller.user.ID, caller.groups, target) != nil {
			continue
		}
		out.Resources = append(out.Resources, mcpResource{Name: resource.Name.String(), URL: scope.String() + "/"})
	}
	return nil, out, nil
}

func callerOf(req *mcp.CallToolRequest) (mcpCaller, error) {
	if req == nil || req.Extra == nil || req.Extra.TokenInfo == nil {
		return mcpCaller{}, errMCPCallerMissing
	}
	caller, ok := req.Extra.TokenInfo.Extra["caller"].(mcpCaller)
	if !ok {
		return mcpCaller{}, errMCPCallerMissing
	}
	return caller, nil
}

// sameHost compares the hosts of two scopes.
func sameHost(a, b tokens.Scope) bool {
	ua, errA := url.Parse(a.String())
	ub, errB := url.Parse(b.String())
	return errA == nil && errB == nil && ua.Host == ub.Host
}

// requestURLOf reads an absolute URL as the URL a grant check asks about.
func requestURLOf(raw string) (access.RequestURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return access.RequestURL{}, access.ErrRequestURL
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return access.ParseRequestURL(u.Scheme, u.Host, path)
}
