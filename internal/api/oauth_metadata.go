package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/oauth"
	"github.com/popoffvg/miniauth/internal/tokens"
)

const (
	authorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	// protectedResourceMetadataPath is served on the host of each protected MCP server.
	// The reverse proxy MUST send this path to miniauth with no forward-auth.
	protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
	oauthAuthorizePath            = "/oauth/authorize"
	oauthTokenPath                = "/oauth/token" // #nosec G101 -- a path, not a secret.
)

// resourceDirectory matches resources by request URL without checking grants.
type resourceDirectory interface {
	MatchResource(ctx context.Context, target access.RequestURL) (access.Resource, error)
	FindResourceByURL(ctx context.Context, url access.ResourceURL) (access.Resource, error)
}

// WithOAuth enables OAuth 2.0 authorization server endpoints and WWW-Authenticate metadata pointers.
func WithOAuth(server *oauth.Service, resources resourceDirectory) RouterOption {
	return func(s *service) {
		s.oauth = server
		s.oauthResources = resources
	}
}

// authorizationServerMetadata is the RFC 8414 metadata document.
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

// protectedResourceMetadata is the RFC 9728 protected resource metadata document.
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

func forwardedTarget(r *http.Request) (proto string, host string, ok bool) {
	proto = strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	if proto != "http" && proto != "https" {
		return "", "", false
	}
	host = strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" || strings.ContainsAny(host, "\r\n/\\@ ?#") {
		return "", "", false
	}
	if _, ok := forwardedHostname(host); !ok {
		return "", "", false
	}
	return proto, host, true
}

// RFC 9728 protected resource metadata handler.
func (s *service) serveProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if !s.isOAuthServerReady() {
		writeProblem(w, http.StatusServiceUnavailable, "The OAuth server is not configured.")
		return
	}
	proto, host, ok := forwardedTarget(r)
	if !ok {
		writeProblem(w, http.StatusNotFound, "No protected resource is at this URL.")
		return
	}
	resourceURL, err := access.ParseResourceURL(proto + "://" + host + "/" + r.PathValue("path"))
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
	resourceIdentifier := proto + "://" + resource.URL.String()
	if scope, err := tokens.ParseScope(resourceIdentifier); err == nil {
		resourceIdentifier = scope.String()
	}
	writeJSON(w, http.StatusOK, protectedResourceMetadata{
		Resource:               resourceIdentifier,
		AuthorizationServers:   []string{s.publicURL.Origin()},
		BearerMethodsSupported: []string{"header"},
	})
}

// RFC 9728 WWW-Authenticate response header builder.
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

// resourceMetadataURL returns the RFC 9728 metadata URL for the target request.
func (s *service) resourceMetadataURL(r *http.Request) string {
	if !s.isOAuthServerReady() {
		return ""
	}
	proto, host, ok := forwardedTarget(r)
	if !ok {
		return ""
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" || !safeForwardedURI(uri) {
		return ""
	}
	target, err := access.ParseRequestURL(proto, host, uri)
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
	metadata := proto + "://" + resource.URL.Host.String() + protectedResourceMetadataPath +
		strings.TrimSuffix(resource.URL.Prefix.String(), "/")
	if strings.ContainsAny(metadata, "\"\\") || !safeHeader(metadata) {
		return ""
	}
	return metadata
}
