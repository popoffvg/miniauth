package api

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// pendingLinkCookieName binds a pending link to the browser. The database stores its SHA-256.
const pendingLinkCookieName = "__Host-id_pending_link"

// linkingFactor is the factor the session MUST hold before a pending link becomes an identity of its user.
const linkingFactor = loginflow.FactorPassword

// linkPagePath confirms a pending link. A page from another site can put its own outside account
// in the pending link cookie, so a password login alone never links: the user confirms on this page.
const linkPagePath = "/link"

const (
	msgLinkFailed pageMessage = "The account was not linked. Try again."
	msgLinkTaken  pageMessage = "This account is linked to another user, or you already have an account of this provider. It was not linked."
)

// linkProviders is the name that the confirm page shows for each outside provider.
var linkProviders = []struct {
	kind users.Kind
	name string
}{
	{kind: users.KindGoogle, name: "Google"},
	{kind: users.KindTelegram, name: "Telegram"},
}

// linkAction is the button of the confirm form.
type linkAction string

const (
	linkActionLink linkAction = "link"
	linkActionSkip linkAction = "skip"
)

// linkPageRequest documents the query of GET /link.
type linkPageRequest struct {
	Return string `query:"return" description:"The page to open after the choice. An https URL under the cookie domain. Any other value opens the default page."`
}

// linkForm documents the form of POST /link.
type linkForm struct {
	Action string `formData:"action" required:"true" enum:"link,skip" description:"link makes the outside account an identity of the session user. skip deletes the pending link."`
	Return string `formData:"return" description:"The page to open after the choice, as in GET /link."`
}

// linkPageView is the data of the link confirm page.
type linkPageView struct {
	Login    users.Login
	Provider string
	Subject  users.Subject
	Return   loginflow.ReturnURL
}

// rememberPendingLink stores the unknown account and asks, with message, for a password login in this browser.
func (s *service) rememberPendingLink(w http.ResponseWriter, r *http.Request, account users.ExternalAccount, flow loginflow.LoginFlow, message pageMessage) {
	secret, err := s.links.Remember(r.Context(), account)
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: remember pending link", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	http.SetCookie(w, hostCookie(pendingLinkCookieName, secret.CookieValue(), identitylink.LinkTTL, time.Now()))
	s.renderSteps(w, r, http.StatusOK, flow, message)
}

// linkConfirmURL is the confirm page when this browser has a pending link and collected holds linkingFactor.
// Else it is empty.
func (s *service) linkConfirmURL(r *http.Request, collected loginflow.Factors, returnURL loginflow.ReturnURL) string {
	if s.links == nil || !collected.Has(linkingFactor) {
		return ""
	}
	if _, err := r.Cookie(pendingLinkCookieName); err != nil {
		return ""
	}
	return s.publicURL.Origin() + linkPagePath + "?return=" + url.QueryEscape(returnURL.String())
}

// pendingLinkSecret reads the pending link cookie. A missing or malformed cookie is identitylink.ErrNotFound.
func pendingLinkSecret(r *http.Request) (identitylink.LinkSecret, error) {
	cookie, err := r.Cookie(pendingLinkCookieName)
	if err != nil {
		return identitylink.LinkSecret{}, identitylink.ErrNotFound
	}
	return identitylink.ParseLinkSecret(cookie.Value)
}

// linkPage names the pending outside account and asks the session user to link it or not.
// With no live pending link, or a session without linkingFactor, it redirects to the return URL.
func (s *service) linkPage(w http.ResponseWriter, r *http.Request) {
	if s.links == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgLoginUnavailable)
		return
	}
	returnURL := ParseReturnURL(r.URL.Query().Get("return"), s.domain, s.publicURL)
	user, session, ok := s.browserPageUser(w, r, linkPagePath, msgLinkFailed)
	if !ok {
		return
	}
	if !session.Factors.Has(linkingFactor) {
		redirectToReturn(w, r, returnURL, http.StatusFound)
		return
	}
	secret, err := pendingLinkSecret(r)
	var link identitylink.PendingLink
	if err == nil {
		link, err = s.links.Pending(r.Context(), secret)
	}
	if errors.Is(err, identitylink.ErrNotFound) {
		http.SetCookie(w, expiredHostCookie(pendingLinkCookieName))
		redirectToReturn(w, r, returnURL, http.StatusFound)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: find pending link", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLinkFailed)
		return
	}
	writePage(w, r, http.StatusOK, linkConfirmPage(linkPageView{
		Login:    user.Login,
		Provider: providerName(link.Account.Kind),
		Subject:  link.Account.Subject,
		Return:   returnURL,
	}), pageCSP)
}

// confirmLink links or discards the pending link of this browser, then redirects to the return URL.
// A store error keeps the cookie, so the user can send the form again.
func (s *service) confirmLink(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.links == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgLoginUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBody)
	if r.ParseForm() != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return
	}
	returnURL := ParseReturnURL(r.PostForm.Get("return"), s.domain, s.publicURL)
	user, session, ok := s.browserPageUser(w, r, linkPagePath, msgLinkFailed)
	if !ok {
		return
	}
	if !session.Factors.Has(linkingFactor) {
		redirectToReturn(w, r, returnURL, http.StatusSeeOther)
		return
	}
	secret, err := pendingLinkSecret(r)
	if err == nil {
		err = s.applyLinkAction(r, linkAction(r.PostForm.Get("action")), secret, user.ID)
	}
	switch {
	case errors.Is(err, errLinkAction):
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return
	case errors.Is(err, identitylink.ErrNotFound):
	case errors.Is(err, identitylink.ErrAccountTaken):
		http.SetCookie(w, expiredHostCookie(pendingLinkCookieName))
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: pending link refused", "user", user.ID.String(), "err", err)
		renderDenied(w, r, http.StatusConflict, msgLinkTaken)
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: confirm pending link", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLinkFailed)
		return
	}
	http.SetCookie(w, expiredHostCookie(pendingLinkCookieName))
	redirectToReturn(w, r, returnURL, http.StatusSeeOther)
}

// errLinkAction means the form names no known action.
var errLinkAction = errors.New("api: link action is not valid")

func (s *service) applyLinkAction(r *http.Request, action linkAction, secret identitylink.LinkSecret, userID users.ID) error {
	switch action {
	case linkActionLink:
		account, err := s.links.Complete(r.Context(), secret, userID)
		if err == nil {
			loggerFrom(r.Context()).InfoContext(r.Context(), "miniauth: identity linked", "user", userID.String(), "kind", account.Kind.String())
		}
		return err
	case linkActionSkip:
		return s.links.Discard(r.Context(), secret)
	default:
		return errLinkAction
	}
}

func providerName(kind users.Kind) string {
	for _, provider := range linkProviders {
		if provider.kind == kind {
			return provider.name
		}
	}
	return kind.String()
}

// redirectToReturn sends the browser to a URL from ParseReturnURL.
func redirectToReturn(w http.ResponseWriter, r *http.Request, returnURL loginflow.ReturnURL, status int) {
	http.Redirect(w, r, returnURL.String(), status) // #nosec G710 -- ParseReturnURL keeps only an https URL that the session cookie reaches.
}
