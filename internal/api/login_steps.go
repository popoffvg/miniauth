package api

import (
	"net/http"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// loginStep is one way to pass a step of the login flow. The fields are exported for the pages.
// Page is the page with the form of the step. An empty Page is a redirect step:
// the pages show it as a button that posts to Path.
// offered is nil for a step the login page always offers.
type loginStep struct {
	Factor  loginflow.Factor
	Path    string
	Label   string
	Page    pageName
	offered func(*service) bool
}

// loginSteps is every step the login page offers, in the order the pages list them.
var loginSteps = []loginStep{
	{Factor: loginflow.FactorPassword, Path: "/login", Label: "Login and password", Page: pageLogin},
	{Factor: loginflow.FactorGoogle, Path: googleLoginPath, Label: "Sign in with Google", offered: (*service).googleOffered},
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
// Every page lists the open redirect steps as buttons.
func (s *service) renderSteps(w http.ResponseWriter, r *http.Request, status int, collected loginflow.Factors, message pageMessage) {
	var forms, buttons []loginStep
	for _, step := range s.openSteps(collected) {
		if step.Page == "" {
			buttons = append(buttons, step)
			continue
		}
		forms = append(forms, step)
	}
	view := pageView{Message: message, Steps: forms, Buttons: buttons, Recovery: s.recovery != nil}
	if len(forms) == 1 {
		renderPage(w, r, status, forms[0].Page, view)
		return
	}
	renderPage(w, r, status, pageSteps, view)
}
