package api

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"

	"github.com/popoffvg/miniauth/internal/users"
)

//go:embed pages/*.html
var pageFiles embed.FS

// pageTemplates names each template by its file name. layout.html defines "head" and "foot".
var pageTemplates = template.Must(template.ParseFS(pageFiles, "pages/*.html"))

// pageName is the file name of one HTML page in pages/.
type pageName string

const (
	pageLogin    pageName = "login.html"
	pageSteps    pageName = "steps.html"
	pageDenied   pageName = "denied.html"
	pageSignedIn pageName = "signed_in.html"
)

// pageMessage is a sentence a page shows to the user. It MUST NOT tell which logins exist.
type pageMessage string

const (
	msgWrongCredentials pageMessage = "The login or the password is wrong."
	msgTooSoon          pageMessage = "Too many failed tries. Try again later."
	msgFlowExpired      pageMessage = "The sign-in form expired. Open the sign-in page again."
	msgCrossOrigin      pageMessage = "The request did not come from the sign-in page."
	msgLoginFailed      pageMessage = "The sign-in failed. Try again."
	msgLoginUnavailable pageMessage = "The sign-in is not available."
	msgBadForm          pageMessage = "The form is not valid."
)

// pageView is the data of every page. A page reads only the fields it needs.
type pageView struct {
	Message pageMessage
	Steps   []loginStep
	Login   users.Login
}

// pageCSP allows inline style and nothing else. form-action is not set:
// a browser applies it to the 303 after the form, and the return URL can be on another subdomain.
const pageCSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"

func renderPage(w http.ResponseWriter, r *http.Request, status int, page pageName, view pageView) {
	var body bytes.Buffer
	if err := pageTemplates.ExecuteTemplate(&body, string(page), view); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: render page", "page", string(page), "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Content-Security-Policy", pageCSP)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "same-origin")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func renderDenied(w http.ResponseWriter, r *http.Request, status int, message pageMessage) {
	renderPage(w, r, status, pageDenied, pageView{Message: message})
}
