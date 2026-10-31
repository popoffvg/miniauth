package api

import (
	"net/http"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// loginStep is one way to pass a step of the login flow. The fields are exported for the pages.
// Page is the page with the form of the step. An empty Page is a redirect step:
// the pages show it as a button that posts to Path.
// widget, when set, puts an outside widget for the step on the view. Such a step has no form and no button.
// offered is nil for a step the login page always offers.
type loginStep struct {
	Factor  loginflow.Factor
	Path    string
	Label   string
	Page    pageName
	widget  func(*service, *pageView)
	offered func(*service) bool
}

// loginSteps is every step the login page offers, in the order the pages list them.
var loginSteps = []loginStep{
	{Factor: loginflow.FactorPassword, Path: "/login", Label: "Login and password", Page: pageLogin},
	{Factor: loginflow.FactorGoogle, Path: googleLoginPath, Label: "Sign in with Google", offered: (*service).googleOffered},
	{Factor: loginflow.FactorTelegram, Path: TelegramCallbackPath, Label: "Sign in with Telegram", widget: (*service).showTelegramWidget, offered: (*service).telegramOffered},
}

// openSteps is the offered steps whose factor the flow has not collected yet.
func (s *service) openSteps(collected loginflow.Factors) []loginStep {
	steps := make([]loginStep, 0, len(loginSteps))
	for _, step := range loginSteps {
		if collected.Has(step.Factor) || (step.offered != nil && !step.offered(s)) {
			continue
		}
		steps = append(steps, step)
	}
	return steps
}

// renderSteps shows the form of the one open form step, or the chooser when more form steps are open.
// Every page lists the open redirect steps as buttons and shows the open widget steps.
func (s *service) renderSteps(w http.ResponseWriter, r *http.Request, status int, collected loginflow.Factors, message pageMessage) {
	view := pageView{Message: message, Recovery: s.recovery != nil}
	for _, step := range s.openSteps(collected) {
		switch {
		case step.widget != nil:
			step.widget(s, &view)
		case step.Page == "":
			view.Buttons = append(view.Buttons, step)
		default:
			view.Steps = append(view.Steps, step)
		}
	}
	if len(view.Steps) == 1 {
		renderPage(w, r, status, view.Steps[0].Page, view)
		return
	}
	renderPage(w, r, status, pageSteps, view)
}
