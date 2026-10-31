package api

import "github.com/popoffvg/miniauth/internal/loginflow"

// loginStep is one way to pass a step of the login flow.
// Page is the page with the form of the step. The fields are exported for the step chooser page.
type loginStep struct {
	Factor loginflow.Factor
	Path   string
	Label  string
	Page   pageName
}

// loginSteps is every step the login page offers, in the order the chooser lists them.
var loginSteps = []loginStep{
	{Factor: loginflow.FactorPassword, Path: "/login", Label: "Login and password", Page: pageLogin},
}

// openSteps is the steps whose factor the flow has not collected yet.
func openSteps(collected loginflow.Factors) []loginStep {
	steps := make([]loginStep, 0, len(loginSteps))
	for _, step := range loginSteps {
		if !collected.Has(step.Factor) {
			steps = append(steps, step)
		}
	}
	return steps
}
