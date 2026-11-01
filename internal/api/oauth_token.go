package api

import (
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/oauth"
)

const (
	grantAuthorizationCode = "authorization_code"
	grantRefreshToken      = "refresh_token"
	// maxTokenRequestBytes fits a code, a verifier, a redirect URI, and a resource, form-encoded.
	maxTokenRequestBytes = 8 << 10
)

// tokenRequest documents the form of POST /oauth/token.
type tokenRequest struct {
	GrantType    string `formData:"grant_type" required:"true" enum:"authorization_code,refresh_token"`
	ClientID     string `formData:"client_id" required:"true" format:"uuid"`
	Code         string `formData:"code" description:"authorization_code only."`
	RedirectURI  string `formData:"redirect_uri" description:"authorization_code only. The same URI as in the authorization request."`
	CodeVerifier string `formData:"code_verifier" description:"authorization_code only. The PKCE verifier."`
	RefreshToken string `formData:"refresh_token" description:"refresh_token only."`
}

// tokenResponse is the RFC 6749 token reply. Its access and refresh tokens are clear text.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Resource     string `json:"resource"`
}

// oauthErrorCode is the OAuth error value in a redirect to the client and in a token error reply.
type oauthErrorCode string

const (
	errInvalidRequest          oauthErrorCode = "invalid_request"
	errInvalidClient           oauthErrorCode = "invalid_client"
	errInvalidGrant            oauthErrorCode = "invalid_grant"
	errInvalidTarget           oauthErrorCode = "invalid_target"
	errUnsupportedGrantType    oauthErrorCode = "unsupported_grant_type"
	errUnsupportedResponseType oauthErrorCode = "unsupported_response_type"
	errAccessDenied            oauthErrorCode = "access_denied"
	errServerError             oauthErrorCode = "server_error"
	errTemporarilyUnavailable  oauthErrorCode = "temporarily_unavailable"
)

// oauthErrorBody is the RFC 6749 error reply of the token endpoint.
type oauthErrorBody struct {
	Error       oauthErrorCode `json:"error"`
	Description string         `json:"error_description"`
}

// exchangeToken is the token endpoint. A public client sends client_id and no secret.
func (s *service) exchangeToken(w http.ResponseWriter, r *http.Request) {
	// The reply holds secrets. No cache may keep it.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if !s.isOAuthServerReady() {
		writeOAuthError(w, http.StatusServiceUnavailable, errTemporarilyUnavailable, "The OAuth server is not configured.")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "The content type must be application/x-www-form-urlencoded.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)
	if r.ParseForm() != nil {
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "The form is not valid.")
		return
	}
	clientID, err := oauth.ParseClientID(r.PostForm.Get("client_id"))
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "The client is not known.")
		return
	}
	var issued oauth.IssuedTokens
	switch r.PostForm.Get("grant_type") {
	case grantAuthorizationCode:
		issued, err = s.exchangeCode(r, clientID)
	case grantRefreshToken:
		var secret oauth.RefreshSecret
		secret, err = oauth.ParseRefreshSecret(r.PostForm.Get("refresh_token"))
		if err == nil {
			issued, err = s.oauth.Refresh(r.Context(), clientID, secret)
		}
	default:
		writeOAuthError(w, http.StatusBadRequest, errUnsupportedGrantType, "The grant type must be authorization_code or refresh_token.")
		return
	}
	switch {
	case errors.Is(err, errTokenRequest):
		writeOAuthError(w, http.StatusBadRequest, errInvalidRequest, "The code, the redirect URI, and the code verifier are required.")
		return
	case errors.Is(err, oauth.ErrClientNotFound):
		writeOAuthError(w, http.StatusUnauthorized, errInvalidClient, "The client is not known.")
		return
	case errors.Is(err, oauth.ErrInvalidGrant):
		writeOAuthError(w, http.StatusBadRequest, errInvalidGrant, "The grant is not valid, was used, or expired.")
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: oauth token", "err", err)
		writeOAuthError(w, http.StatusInternalServerError, errServerError, "The token request failed.")
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  issued.Access.Reveal(),
		TokenType:    "Bearer",
		ExpiresIn:    int64(oauth.AccessTokenLifetime / time.Second),
		RefreshToken: issued.Refresh.Reveal(),
		Resource:     issued.Resource.String(),
	})
}

var errTokenRequest = errors.New("api: token request misses a field")

func (s *service) exchangeCode(r *http.Request, clientID oauth.ClientID) (oauth.IssuedTokens, error) {
	form := r.PostForm
	if form.Get("code") == "" || form.Get("redirect_uri") == "" || form.Get("code_verifier") == "" {
		return oauth.IssuedTokens{}, errTokenRequest
	}
	code, err := oauth.ParseCode(form.Get("code"))
	if err != nil {
		return oauth.IssuedTokens{}, err
	}
	redirect, err := oauth.ParseRedirectURI(form.Get("redirect_uri"))
	if err != nil {
		return oauth.IssuedTokens{}, oauth.ErrInvalidGrant
	}
	verifier, err := oauth.ParseVerifier(form.Get("code_verifier"))
	if err != nil {
		return oauth.IssuedTokens{}, err
	}
	return s.oauth.ExchangeCode(r.Context(), clientID, code, redirect, verifier)
}

func writeOAuthError(w http.ResponseWriter, status int, code oauthErrorCode, description string) {
	writeJSON(w, status, oauthErrorBody{Error: code, Description: description})
}
