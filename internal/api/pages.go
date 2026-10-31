package api

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"

	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

//go:embed pages/*.html
var pageFiles embed.FS

// pageTemplates names each template by its file name. layout.html defines "head" and "foot".
var pageTemplates = template.Must(template.ParseFS(pageFiles, "pages/*.html"))

// pageName is the file name of one HTML page in pages/.
type pageName string

const (
	pageLogin       pageName = "login.html"
	pageSteps       pageName = "steps.html"
	pageDenied      pageName = "denied.html"
	pageSignedIn    pageName = "signed_in.html"
	pageStepUp      pageName = "step_up.html"
	pageTokens      pageName = "tokens.html"
	pageRecover     pageName = "recover.html"
	pageRecoverSent pageName = "recover_sent.html"
	pageReset       pageName = "reset.html"
	pageResetDone   pageName = "reset_done.html"
	pageInvite      pageName = "invite.html"
	// pageTokenCreated shows the clear token. The handler MUST set Cache-Control: no-store.
	pageTokenCreated pageName = "token_created.html"
)

// pageMessage is a sentence a page shows to the user. It MUST NOT tell which logins exist,
// except on the invite form, which needs an open invite.
type pageMessage string

const (
	msgWrongCredentials    pageMessage = "The login or the password is wrong."
	msgTooSoon             pageMessage = "Too many failed tries. Try again later."
	msgFlowExpired         pageMessage = "The sign-in form expired. Open the sign-in page again."
	msgCrossOrigin         pageMessage = "The request did not come from the sign-in page."
	msgLoginFailed         pageMessage = "The sign-in failed. Try again."
	msgLoginUnavailable    pageMessage = "The sign-in is not available."
	msgBadForm             pageMessage = "The form is not valid."
	msgRecoverySent        pageMessage = "If the address is known, a link is on its way."
	msgRecoveryOff         pageMessage = "Password recovery is not available."
	msgRecoveryFailed      pageMessage = "The password recovery failed. Try again."
	msgResetLinkInvalid    pageMessage = "The link is not valid, was used, or expired. Ask for a new link."
	msgNewPasswordInvalid  pageMessage = "The password is not valid. It must have 1 to 1024 bytes."
	msgLinkGoogle          pageMessage = "Sign in with your password to link this Google account."
	msgGoogleFailed        pageMessage = "The Google sign-in failed. Try again."
	msgGoogleUnavailable   pageMessage = "The Google sign-in is not available."
	msgLinkTelegram        pageMessage = "Sign in with your password to link this Telegram account."
	msgTelegramFailed      pageMessage = "The Telegram sign-in failed. Try again."
	msgTelegramUnavailable pageMessage = "The Telegram sign-in is not available."
)

// pageView is the data of every page. A page reads only the fields it needs.
type pageView struct {
	Message  pageMessage
	Steps    []loginStep
	Buttons  []loginStep
	Login    users.Login
	Telegram telegramWidget
	Tokens   []tokens.Token
	// NewToken is set only on pageTokenCreated.
	NewToken *tokens.Secret
	// Recovery shows the "Forgot password" link.
	Recovery bool
	// ResetToken goes to the hidden field of the new password form, never to a URL.
	ResetToken recovery.Token
	// Invite goes to the hidden field of the invite form, never to a URL.
	Invite invites.Token
}

// pageCSP allows inline style and nothing else. form-action is not set:
// a browser applies it to the 303 after the form, and the return URL can be on another subdomain.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"

// telegramPageCSP also allows the widget script from telegram.org and the widget frame it opens
// from oauth.telegram.org. The script itself navigates to the callback, so no inline script is needed.
const telegramPageCSP = "default-src 'none'; script-src https://telegram.org; frame-src https://oauth.telegram.org; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"

// pageCSPOf is telegramPageCSP for a pageView that shows the Telegram widget, else pageCSP.
func pageCSPOf(view any) string {
	if v, ok := view.(pageView); ok && v.Telegram != (telegramWidget{}) {
		return telegramPageCSP
	}
	return pageCSP
}

// view is a pageView, or the view type of a page that has its own.
func renderPage(w http.ResponseWriter, r *http.Request, status int, page pageName, view any) {
	var body bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&body, string(page), view); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: render page", "page", string(page), "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Security-Policy", pageCSPOf(view))
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	if header.Get("Referrer-Policy") == "" {
		header.Set("Referrer-Policy", "same-origin")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func renderDenied(w http.ResponseWriter, r *http.Request, status int, message pageMessage) {
	renderPage(w, r, status, pageDenied, pageView{Message: message})
}
