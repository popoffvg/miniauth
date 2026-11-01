package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/oauth"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	msgOAuthUnavailable pageMessage = "The app sign-in is not available."
	msgOAuthClient      pageMessage = "The app is not known. Ask the admin to register it."
	msgOAuthRedirect    pageMessage = "The app asked to return to an address it did not register."
	msgOAuthFailed      pageMessage = "The app sign-in failed. Try again."
)

// consentActionAllow and consentActionDeny are the buttons of the consent page.
const (
	consentActionAllow = "allow"
	consentActionDeny  = "deny"
)

// authorizeParams are the query names of authorizeRequest in field order: the parameters the consent form sends again.
// The POST checks them again: a hidden field is not trusted.
var authorizeParams = queryParamNames(reflect.TypeFor[authorizeRequest]())

func queryParamNames(request reflect.Type) []string {
	var names []string
	for i := range request.NumField() {
		if name, ok := request.Field(i).Tag.Lookup("query"); ok {
			names = append(names, name)
		}
	}
	return names
}

// authorizeRequest documents the query of GET /oauth/authorize and the consent form.
// A field with a query tag is a parameter the consent form sends again; the button has none.
type authorizeRequest struct {
	ResponseType        string `query:"response_type" formData:"response_type" required:"true" enum:"code"`
	ClientID            string `query:"client_id" formData:"client_id" required:"true" format:"uuid"`
	RedirectURI         string `query:"redirect_uri" formData:"redirect_uri" required:"true" format:"uri"`
	CodeChallenge       string `query:"code_challenge" formData:"code_challenge" required:"true"`
	CodeChallengeMethod string `query:"code_challenge_method" formData:"code_challenge_method" required:"true" enum:"S256"`
	State               string `query:"state" formData:"state"`
	Resource            string `query:"resource" formData:"resource" required:"true" format:"uri" description:"The URL of the MCP server. It MUST be a resource of the access API."`
	Action              string `formData:"action" enum:"allow,deny" description:"The consent form only."`
}

// An untrusted redirect URI MUST render a page. Errors MUST NOT go to the client URI.
type authorizeRefusal struct {
	message pageMessage
	code    oauthErrorCode
}

type consentPageView struct {
	Login        users.Login
	ClientName   oauth.ClientName
	RedirectHost string
	Resource     tokens.Scope
	Fields       []consentField
}

type consentField struct {
	Name  string
	Value string
}

// RFC 6749 Section 3.1 authorization endpoint.
func (s *service) authorizePage(w http.ResponseWriter, r *http.Request) {
	if !s.isOAuthServerReady() {
		renderDenied(w, r, http.StatusServiceUnavailable, msgOAuthUnavailable)
		return
	}
	request, refusal, err := s.readAuthorizeRequest(r.Context(), r.URL.Query())
	if s.writeAuthorizeRefusal(w, r, request, refusal, err, http.StatusFound) {
		return
	}
	user, _, ok := s.browserPageUser(w, r, oauthAuthorizePath+"?"+r.URL.RawQuery, msgOAuthFailed)
	if !ok {
		return
	}
	isApproved, err := s.oauth.HasConsent(r.Context(), user.ID, request)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: oauth consent", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgOAuthFailed)
		return
	}
	if isApproved {
		s.sendCode(w, r, user, request, http.StatusFound)
		return
	}
	fields := make([]consentField, 0, len(authorizeParams))
	for _, name := range authorizeParams {
		fields = append(fields, consentField{Name: name, Value: r.URL.Query().Get(name)})
	}
	writePage(w, r, http.StatusOK, consentPage(consentPageView{
		Login:        user.Login,
		ClientName:   request.Client.Name,
		RedirectHost: request.RedirectURI.Host(),
		Resource:     request.Resource,
		Fields:       fields,
	}), pageCSP)
}

func (s *service) answerConsent(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if !s.isOAuthServerReady() {
		renderDenied(w, r, http.StatusServiceUnavailable, msgOAuthUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBody)
	if r.ParseForm() != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return
	}
	request, refusal, err := s.readAuthorizeRequest(r.Context(), r.PostForm)
	if s.writeAuthorizeRefusal(w, r, request, refusal, err, http.StatusSeeOther) {
		return
	}
	query := url.Values{}
	for _, name := range authorizeParams {
		query.Set(name, r.PostForm.Get(name))
	}
	user, _, ok := s.browserPageUser(w, r, oauthAuthorizePath+"?"+query.Encode(), msgOAuthFailed)
	if !ok {
		return
	}
	switch r.PostForm.Get("action") {
	case consentActionAllow:
		s.sendCode(w, r, user, request, http.StatusSeeOther)
	case consentActionDeny:
		s.redirectToClient(w, r, request, url.Values{"error": {string(errAccessDenied)}}, http.StatusSeeOther)
	default:
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
	}
}

func (s *service) sendCode(w http.ResponseWriter, r *http.Request, user users.User, request oauth.AuthorizeRequest, status int) {
	code, err := s.oauth.Approve(r.Context(), user.ID, request)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: oauth approve", "err", err)
		s.redirectToClient(w, r, request, url.Values{"error": {string(errServerError)}}, status)
		return
	}
	// The code is in this Location only. Referrer-Policy keeps the client page from passing it on.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	s.redirectToClient(w, r, request, url.Values{"code": {code.Reveal()}}, status)
}

// RFC 9207 Section 2 requires iss parameter on authorization responses to prevent mix-up attacks.
func (s *service) redirectToClient(w http.ResponseWriter, r *http.Request, request oauth.AuthorizeRequest, params url.Values, status int) {
	params.Set("iss", s.publicURL.Origin())
	if state := request.State.String(); state != "" {
		params.Set("state", state)
	}
	http.Redirect(w, r, request.RedirectURI.WithParams(params), status)
}

func (s *service) writeAuthorizeRefusal(w http.ResponseWriter, r *http.Request, request oauth.AuthorizeRequest, refusal authorizeRefusal, err error, status int) bool {
	switch {
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: oauth authorize", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgOAuthFailed)
	case refusal.message != "":
		renderDenied(w, r, http.StatusBadRequest, refusal.message)
	case refusal.code != "":
		s.redirectToClient(w, r, request, url.Values{"error": {string(refusal.code)}}, status)
	default:
		return false
	}
	return true
}

// readAuthorizeRequest checks the client and the redirect URI first: until both pass, no error may go to the redirect URI.
func (s *service) readAuthorizeRequest(ctx context.Context, values url.Values) (oauth.AuthorizeRequest, authorizeRefusal, error) {
	clientID, err := oauth.ParseClientID(values.Get("client_id"))
	if err != nil {
		return oauth.AuthorizeRequest{}, authorizeRefusal{message: msgOAuthClient}, nil
	}
	client, err := s.oauth.FindClient(ctx, clientID)
	if errors.Is(err, oauth.ErrClientNotFound) {
		return oauth.AuthorizeRequest{}, authorizeRefusal{message: msgOAuthClient}, nil
	}
	if err != nil {
		return oauth.AuthorizeRequest{}, authorizeRefusal{}, err
	}
	redirect, err := oauth.ParseRedirectURI(values.Get("redirect_uri"))
	if err != nil || !client.Allows(redirect) {
		return oauth.AuthorizeRequest{}, authorizeRefusal{message: msgOAuthRedirect}, nil
	}
	request := oauth.AuthorizeRequest{Client: client, RedirectURI: redirect}
	state, err := oauth.ParseState(values.Get("state"))
	if err != nil {
		return request, authorizeRefusal{code: errInvalidRequest}, nil
	}
	request.State = state
	if values.Get("response_type") != "code" {
		return request, authorizeRefusal{code: errUnsupportedResponseType}, nil
	}
	request.Challenge, err = oauth.ParseChallenge(values.Get("code_challenge"), values.Get("code_challenge_method"))
	if err != nil {
		return request, authorizeRefusal{code: errInvalidRequest}, nil
	}
	request.Resource, err = s.oauthResource(ctx, values.Get("resource"))
	if errors.Is(err, errNotAResource) {
		return request, authorizeRefusal{code: errInvalidTarget}, nil
	}
	if err != nil {
		return request, authorizeRefusal{}, err
	}
	return request, authorizeRefusal{}, nil
}

var errNotAResource = errors.New("api: oauth resource is not a resource of the access API")

// oauthResource reads the resource parameter. The value MUST equal the host and the prefix of a stored resource.
// That keeps a token on one MCP server, and /auth/check still asks for a grant on it.
func (s *service) oauthResource(ctx context.Context, raw string) (tokens.Scope, error) {
	scope, err := tokens.ParseScope(raw)
	if err != nil {
		return tokens.Scope{}, errNotAResource
	}
	resourceURL, err := access.ParseResourceURL(raw)
	if err != nil {
		return tokens.Scope{}, errNotAResource
	}
	_, err = s.oauthResources.FindResourceByURL(ctx, resourceURL)
	if errors.Is(err, access.ErrResourceNotFound) {
		return tokens.Scope{}, errNotAResource
	}
	if err != nil {
		return tokens.Scope{}, err
	}
	return scope, nil
}
