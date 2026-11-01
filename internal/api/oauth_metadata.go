package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/oauth"
)

const (
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	// protectedResourceMetadataPath is served on the host of each protected MCP server.
	// The reverse proxy MUST send this path to miniauth with no forward-auth.
	protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
	oauthAuthorizePath            = "/oauth/authorize"
	oauthTokenPath                = "/oauth/token" // #nosec G101 -- a path, not a secret.
)

// resourceDirectory names the resource of a URL for the OAuth routes and /auth/check. It reads no grant.
type resourceDirectory interface {
	MatchResource(ctx context.Context, target access.RequestURL) (access.Resource, error)
	FindResourceByURL(ctx context.Context, url access.ResourceURL) (access.Resource, error)
}

// WithOAuth serves the OAuth authorization server for MCP clients.
// Without it, the OAuth routes answer 503 and /auth/check names no resource metadata.
func WithOAuth(server *oauth.Service, resources resourceDirectory) RouterOption {
	return func(s *service) {
		s.oauth = server
		s.oauthResources = resources
	}
}

// authorizationServerMetadata is the RFC 8414 document. The issuer is the public origin.
type authorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IssParameterSupported             bool     `json:"authorization_response_iss_parameter_supported"`
}

// protectedResourceMetadata is the RFC 9728 document of one resource.
type protectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
}

type protectedResourcePath struct {
	Path string `path:"path" description:"The path prefix of the resource, with no leading slash."`
}

func (s *service) isOAuthServerReady() bool {
	return s.oauth != nil && s.oauthResources != nil && s.publicURL.Origin() != ""
}

func (s *service) serveAuthorizationServerMetadata(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if !s.isOAuthServerReady() {
		writeProblem(w, http.StatusServiceUnavailable, "The OAuth server is not configured.")
		return
	}
	origin := s.publicURL.Origin()
	writeJSON(w, http.StatusOK, authorizationServerMetadata{
		Issuer:                            origin,
		AuthorizationEndpoint:             origin + oauthAuthorizePath,
		TokenEndpoint:                     origin + oauthTokenPath,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{grantAuthorizationCode, grantRefreshToken},
		CodeChallengeMethodsSupported:     []string{oauth.ChallengeMethodS256},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		IssParameterSupported:             true,
	})
}

// protectedResourceMetadata answers for the resource whose host is X-Forwarded-Host and whose prefix is the path.
// A URL that is not exactly a resource is 404.
func (s *service) serveProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if !s.isOAuthServerReady() {
		writeProblem(w, http.StatusServiceUnavailable, "The OAuth server is not configured.")
		return
	}
	forwarded, ok := forwardedURL(r, s.domain, s.publicURL)
	if !ok {
		writeProblem(w, http.StatusNotFound, "No protected resource is at this URL.")
		return
	}
	resourceURL, err := access.ParseResourceURL(forwarded.proto + "://" + forwarded.host + "/" + r.PathValue("path"))
	if err != nil {
		writeProblem(w, http.StatusNotFound, "No protected resource is at this URL.")
		return
	}
	resource, err := s.oauthResources.FindResourceByURL(r.Context(), resourceURL)
	if errors.Is(err, access.ErrResourceNotFound) {
		writeProblem(w, http.StatusNotFound, "No protected resource is at this URL.")
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: protected resource metadata", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The metadata lookup failed.")
		return
	}
	writeJSON(w, http.StatusOK, protectedResourceMetadata{
		Resource:               forwarded.proto + "://" + resource.URL.String(),
		AuthorizationServers:   []string{s.publicURL.Origin()},
		BearerMethodsSupported: []string{"header"},
	})
}

// bearerChallenge is the WWW-Authenticate value of a 401 from /auth/check.
// With OAuth on, it names the metadata of the resource that covers the forwarded URL,
// so an MCP client finds the authorization server.
func (s *service) bearerChallenge(r *http.Request, isInvalidToken bool) string {
	var params []string
	if isInvalidToken {
		params = append(params, `error="invalid_token"`)
	}
	if metadata := s.resourceMetadataURL(r); metadata != "" {
		params = append(params, `resource_metadata="`+metadata+`"`)
	}
	if len(params) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(params, ", ")
}

// resourceMetadataURL is empty when OAuth is off or no resource covers the forwarded URL.
func (s *service) resourceMetadataURL(r *http.Request) string {
	if !s.isOAuthServerReady() {
		return ""
	}
	forwarded, ok := forwardedURL(r, s.domain, s.publicURL)
	if !ok || forwarded.uri == "" {
		return ""
	}
	target, err := access.ParseRequestURL(forwarded.proto, forwarded.host, forwarded.uri)
	if err != nil {
		return ""
	}
	resource, err := s.oauthResources.MatchResource(r.Context(), target)
	if err != nil {
		if !errors.Is(err, access.ErrNoResource) {
			loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: resource metadata lookup", "err", err)
		}
		return ""
	}
	metadata := forwarded.proto + "://" + resource.URL.Host.String() + protectedResourceMetadataPath +
		strings.TrimSuffix(resource.URL.Prefix.String(), "/")
	if strings.ContainsAny(metadata, "\"\\") || !safeHeader(metadata) {
		return ""
	}
	return metadata
}
