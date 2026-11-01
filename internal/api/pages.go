package api

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/a-h/templ"

	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// pageName names one page that reads a pageView.
type pageName string

const (
	pageLogin       pageName = "login"
	pageSteps       pageName = "steps"
	pageDenied      pageName = "denied"
	pageStepUp      pageName = "step-up"
	pageTokens      pageName = "tokens"
	pageRecover     pageName = "recover"
	pageRecoverSent pageName = "recover-sent"
	pageReset       pageName = "reset"
	pageResetDone   pageName = "reset-done"
	pageInvite      pageName = "invite"
	// pageAddKey is the form that adds a passkey. It loads passkey.js. The handler MUST set Script in the view.
	pageAddKey pageName = "passkey-new"
	// pageTokenCreated shows the clear token. The handler MUST set Cache-Control: no-store.
	pageTokenCreated pageName = "token-created"
	pageTOTP         pageName = "totp"
	pageRecoveryCode pageName = "recovery-code"
	// pageTOTPEnroll shows the TOTP secret. The handler MUST set Cache-Control: no-store.
	pageTOTPEnroll pageName = "totp-enroll"
	// pageRecoveryCodes shows the clear recovery codes. The handler MUST set Cache-Control: no-store.
	pageRecoveryCodes pageName = "recovery-codes"
)

// pageComponents is the templ component of each pageName.
var pageComponents = map[pageName]func(pageView) templ.Component{
	pageLogin:         loginForm,
	pageSteps:         stepChooser,
	pageDenied:        deniedPage,
	pageStepUp:        stepUpForm,
	pageTokens:        tokensPage,
	pageRecover:       recoverForm,
	pageRecoverSent:   recoverSentPage,
	pageReset:         resetForm,
	pageResetDone:     resetDonePage,
	pageInvite:        inviteForm,
	pageAddKey:        passkeyNewPage,
	pageTokenCreated:  tokenCreatedPage,
	pageTOTP:          totpForm,
	pageRecoveryCode:  recoveryCodeForm,
	pageTOTPEnroll:    totpEnrollPage,
	pageRecoveryCodes: recoveryCodesPage,
}

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
	// Shell is the signed-in user and the menu. A page of the app shell MUST have it.
	Shell   shellView
	Message pageMessage
	// Notice is the result of the last change, from the done query flag.
	Notice pageMessage
	// Prompt tells why the page asks for something. It is not an error.
	Prompt pageMessage
	Steps  []loginStep
	// Links are the other open form steps next to the form of one step.
	Links    []loginStep
	Buttons  []loginStep
	Login    users.Login
	Telegram telegramWidget
	Tokens   tokenTable
	// TokenForm is the form of a refused POST /tokens. It holds no secret.
	TokenForm tokenForm
	// NewToken is set only on pageTokenCreated.
	NewToken *tokens.Secret
	// Recovery shows the "Forgot password" link.
	Recovery bool
	// ResetToken goes to the hidden field of the new password form, never to a URL.
	ResetToken recovery.Token
	// Invite goes to the hidden field of the invite form, never to a URL.
	Invite invites.Token
	// Script loads passkey.js and adds passkeySources to the CSP.
	Script bool
	// Enrollment is set only on pageTOTPEnroll.
	Enrollment *enrollmentView
	// RecoveryCodes is set only on pageRecoveryCodes.
	RecoveryCodes []totp.RecoveryCode
}

// pageCSP allows the stylesheet of this origin and nothing else. form-action is not set:
// a browser applies it to the 303 after the form, and the return URL can be on another subdomain.
var pageCSP = buildCSP()

// cspSource is one source that a page feature adds to one CSP directive.
type cspSource struct {
	directive string
	source    string
}

// cspDirectives is the order of the directives a page feature can open. Every other directive is closed.
var cspDirectives = []string{"script-src", "connect-src", "frame-src"}

// passkeySources load passkey.js from this origin and let it fetch this origin.
var passkeySources = []cspSource{
	{directive: "script-src", source: "'self'"},
	{directive: "connect-src", source: "'self'"},
}

// telegramSources allow the widget script from telegram.org and the widget frame it opens
// from oauth.telegram.org. The script itself navigates to the callback, so no inline script is needed.
var telegramSources = []cspSource{
	{directive: "script-src", source: "https://telegram.org"},
	{directive: "frame-src", source: "https://oauth.telegram.org"},
}

var (
	scriptPageCSP   = buildCSP(passkeySources)
	telegramPageCSP = buildCSP(telegramSources)
)

// buildCSP is pageCSP with the sources of each feature. Two features on one page add up.
func buildCSP(features ...[]cspSource) string {
	parts := []string{"default-src 'none'"}
	for _, directive := range cspDirectives {
		var sources []string
		for _, feature := range features {
			for _, source := range feature {
				if source.directive == directive {
					sources = append(sources, source.source)
				}
			}
		}
		if len(sources) > 0 {
			parts = append(parts, directive+" "+strings.Join(sources, " "))
		}
	}
	return strings.Join(append(parts, "style-src 'self'", "base-uri 'none'", "frame-ancestors 'none'"), "; ")
}

// pageCSPOf adds the sources of the passkey script and of the Telegram widget when the view shows them.
func pageCSPOf(view pageView) string {
	var features [][]cspSource
	if view.Script {
		features = append(features, passkeySources)
	}
	if view.Telegram != (telegramWidget{}) {
		features = append(features, telegramSources)
	}
	return buildCSP(features...)
}

// renderPage writes the page of name with view.
func renderPage(w http.ResponseWriter, r *http.Request, status int, name pageName, view pageView) {
	component, ok := pageComponents[name]
	if !ok {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: render page: no component", "page", string(name))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writePage(w, r, status, component(view), pageCSPOf(view))
}

// writePage renders page first, so a render error still answers 500 with no partial body.
func writePage(w http.ResponseWriter, r *http.Request, status int, page templ.Component, csp string) {
	var body bytes.Buffer
	if err := page.Render(r.Context(), &body); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: render page", "path", r.URL.Path, "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Security-Policy", csp)
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
