package api

import (
	"net/http"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

const (
	loginTOTPPath         = "/login/totp"
	loginRecoveryCodePath = "/login/recovery-code"
)

// loginStep is one way to pass a step of the login flow. The fields are exported for the pages.
// Page is the page with the form of the step. An empty Page is a redirect step:
// the pages show it as a button that posts to Path.
// widget, when set, puts an outside widget for the step on the view. Such a step has no form and no button.
// A Script button runs a WebAuthn ceremony in passkey.js instead of a form post.
// offered is nil for a step the login page always offers.
// Second is true for a step that counts only after the first factor of a user with TOTP.
// Fallback is true for a step that a page offers only as a link next to the form of another step.
// Icon is the icon of the step button or link.
type loginStep struct {
	Factor   loginflow.Factor
	Path     string
	Label    string
	Page     pageName
	Script   bool
	Second   bool
	Fallback bool
	Icon     iconName
	widget   func(*service, *pageView)
	offered  func(*service) bool
}

// loginSteps is every step the login page offers, in the order the pages list them.
var loginSteps = []loginStep{
	{Factor: loginflow.FactorPassword, Path: "/login", Label: "Login and password", Icon: iconLock, Page: pageLogin},
	{Factor: loginflow.FactorGoogle, Path: googleLoginPath, Label: "Sign in with Google", Icon: iconGoogle, offered: (*service).googleOffered},
	{Factor: loginflow.FactorTelegram, Path: TelegramCallbackPath, Label: "Sign in with Telegram", widget: (*service).showTelegramWidget, offered: (*service).telegramOffered},
	{Factor: loginflow.FactorPasskey, Path: passkeyLoginPath, Label: "Sign in with a passkey", Icon: iconPasskey, Script: true, offered: (*service).passkeyOffered},
	{Factor: loginflow.FactorTOTP, Path: loginTOTPPath, Label: "Code from the authenticator app", Icon: iconPhone, Page: pageTOTP, Second: true, offered: (*service).totpOffered},
	{Factor: loginflow.FactorRecovery, Path: loginRecoveryCodePath, Label: "Use a recovery code", Icon: iconKey, Page: pageRecoveryCode, Second: true, Fallback: true, offered: (*service).totpOffered},
}

// openSteps is the offered steps of the stage of flow whose factor the flow has not collected yet.
// A flow that needs a second factor offers only the Second steps.
func (s *service) openSteps(flow loginflow.LoginFlow) []loginStep {
	steps := make([]loginStep, 0, len(loginSteps))
	for _, step := range loginSteps {
		if step.Second != flow.NeedsSecond || flow.Factors.Has(step.Factor) || (step.offered != nil && !step.offered(s)) {
			continue
		}
		steps = append(steps, step)
	}
	return steps
}

// findStep returns the step of factor in steps.
func findStep(steps []loginStep, factor loginflow.Factor) (loginStep, bool) {
	for _, step := range steps {
		if step.Factor == factor {
			return step, true
		}
	}
	return loginStep{}, false
}

// renderSteps shows the form of the one open form step that is not a Fallback, or the chooser when more are open.
func (s *service) renderSteps(w http.ResponseWriter, r *http.Request, status int, flow loginflow.LoginFlow, message pageMessage) {
	s.renderStep(w, r, status, flow, 0, message)
}

// renderStep shows the form of the open step of factor, or of the one open form step when factor is 0.
// The other open form steps become Links. With no such step it shows the chooser.
// Every page lists the open redirect steps as buttons and shows the open widget steps.
// A Script button loads passkey.js.
func (s *service) renderStep(w http.ResponseWriter, r *http.Request, status int, flow loginflow.LoginFlow, factor loginflow.Factor, message pageMessage) {
	view := pageView{Message: message, Recovery: s.recovery != nil && !flow.NeedsSecond}
	var forms []loginStep
	for _, step := range s.openSteps(flow) {
		switch {
		case step.widget != nil:
			step.widget(s, &view)
		case step.Page == "":
			view.Buttons = append(view.Buttons, step)
			view.Script = view.Script || step.Script
		default:
			forms = append(forms, step)
		}
	}
	shown, ok := chooseForm(forms, factor)
	if !ok {
		view.Steps = forms
		renderPage(w, r, status, pageSteps, view)
		return
	}
	for _, step := range forms {
		if step.Factor != shown.Factor {
			view.Links = append(view.Links, step)
		}
	}
	renderPage(w, r, status, shown.Page, view)
}

// chooseForm returns the form of factor, or the one form that is not a Fallback when factor is 0.
func chooseForm(forms []loginStep, factor loginflow.Factor) (loginStep, bool) {
	var found []loginStep
	for _, step := range forms {
		if factor != 0 && step.Factor == factor || factor == 0 && !step.Fallback {
			found = append(found, step)
		}
	}
	if len(found) != 1 {
		return loginStep{}, false
	}
	return found[0], true
}
