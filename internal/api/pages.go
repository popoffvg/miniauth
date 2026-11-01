package api

import (
	"net/http"
	"strings"

	"github.com/a-h/templ"

	"github.com/popoffvg/miniauth/internal/views"
)

const (
	msgWrongCredentials    views.Message = "The login or the password is wrong."
	msgTooSoon             views.Message = "Too many failed tries. Try again later."
	msgFlowExpired         views.Message = "The sign-in form expired. Open the sign-in page again."
	msgCrossOrigin         views.Message = "The request did not come from the sign-in page."
	msgLoginFailed         views.Message = "The sign-in failed. Try again."
	msgLoginUnavailable    views.Message = "The sign-in is not available."
	msgBadForm             views.Message = "The form is not valid."
	msgRecoverySent        views.Message = "If the address is known, a link is on its way."
	msgRecoveryOff         views.Message = "Password recovery is not available."
	msgRecoveryFailed      views.Message = "The password recovery failed. Try again."
	msgResetLinkInvalid    views.Message = "The link is not valid, was used, or expired. Ask for a new link."
	msgNewPasswordInvalid  views.Message = "The password is not valid. It must have 1 to 1024 bytes."
	msgLinkGoogle          views.Message = "Sign in with your password to link this Google account."
	msgGoogleFailed        views.Message = "The Google sign-in failed. Try again."
	msgGoogleUnavailable   views.Message = "The Google sign-in is not available."
	msgLinkTelegram        views.Message = "Sign in with your password to link this Telegram account."
	msgTelegramFailed      views.Message = "The Telegram sign-in failed. Try again."
	msgTelegramUnavailable views.Message = "The Telegram sign-in is not available."
)

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
func pageCSPOf(view views.Page) string {
	var features [][]cspSource
	if view.Script {
		features = append(features, passkeySources)
	}
	if view.Telegram != (views.TelegramWidget{}) {
		features = append(features, telegramSources)
	}
	return buildCSP(features...)
}

// renderPage writes the page of name with view.
func renderPage(w http.ResponseWriter, r *http.Request, status int, name views.PageName, view views.Page) {
	component, ok := views.PageOf(name, view)
	if !ok {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: render page: no component", "page", string(name))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writePage(w, r, status, component, pageCSPOf(view))
}

// writePage renders page first, so a render error still answers 500 with no partial body.
func writePage(w http.ResponseWriter, r *http.Request, status int, page templ.Component, csp string) {
	body, err := views.Render(r.Context(), page)
	if err != nil {
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
	_, _ = w.Write(body)
}

func renderDenied(w http.ResponseWriter, r *http.Request, status int, message views.Message) {
	renderPage(w, r, status, views.PageDenied, views.Page{Message: message})
}
