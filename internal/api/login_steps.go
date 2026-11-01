package api

import (
	"net/http"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/views"
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
	Page     views.PageName
	Script   bool
	Second   bool
	Fallback bool
	Icon     views.Icon
	widget   func(*service, *http.Request, *views.Page)
	offered  func(*service) bool
}

// loginSteps is every step the login page offers, in the order the pages list them.
var loginSteps = []loginStep{
	{Factor: loginflow.FactorPassword, Path: "/login", Label: "Login and password", Icon: views.IconLock, Page: views.PageLogin},
	{Factor: loginflow.FactorGoogle, Path: googleLoginPath, Label: "Sign in with Google", Icon: views.IconGoogle, offered: (*service).googleOffered},
	{Factor: loginflow.FactorTelegram, Path: TelegramCallbackPath, Label: "Sign in with Telegram", widget: (*service).showTelegramWidget, offered: (*service).telegramOffered},
	{Factor: loginflow.FactorPasskey, Path: passkeyLoginPath, Label: "Sign in with a passkey", Icon: views.IconPasskey, Script: true, offered: (*service).passkeyOffered},
	{Factor: loginflow.FactorTOTP, Path: loginTOTPPath, Label: "Code from the authenticator app", Icon: views.IconPhone, Page: views.PageTOTP, Second: true, offered: (*service).totpOffered},
	{Factor: loginflow.FactorRecovery, Path: loginRecoveryCodePath, Label: "Use a recovery code", Icon: views.IconKey, Page: views.PageRecoveryCode, Second: true, Fallback: true, offered: (*service).totpOffered},
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
func (s *service) renderSteps(w http.ResponseWriter, r *http.Request, status int, flow loginflow.LoginFlow, message views.Message) {
	s.renderStep(w, r, status, flow, 0, message)
}

// renderStep shows the form of the open step of factor, or of the one open form step when factor is 0.
// The other open form steps become Links. With no such step it shows the chooser.
// Every page lists the open redirect steps as buttons and shows the open widget steps.
// A Script button loads passkey.js.
func (s *service) renderStep(w http.ResponseWriter, r *http.Request, status int, flow loginflow.LoginFlow, factor loginflow.Factor, message views.Message) {
	view := views.Page{Message: message, Recovery: s.recovery != nil && !flow.NeedsSecond}
	var forms []loginStep
	for _, step := range s.openSteps(flow) {
		switch {
		case step.widget != nil:
			step.widget(s, r, &view)
		case step.Page == "":
			view.Buttons = append(view.Buttons, step.view())
			view.Script = view.Script || step.Script
		default:
			forms = append(forms, step)
		}
	}
	shown, ok := chooseForm(forms, factor)
	if !ok {
		for _, step := range forms {
			view.Steps = append(view.Steps, step.view())
		}
		renderPage(w, r, status, views.PageSteps, view)
		return
	}
	for _, step := range forms {
		if step.Factor != shown.Factor {
			view.Links = append(view.Links, step.view())
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

// view is the step as a page shows it.
func (step loginStep) view() views.Step {
	return views.Step{Path: step.Path, Label: step.Label, Icon: step.Icon, Script: step.Script}
}
