package loginflow

import "fmt"

// FlowKind is what a completed flow does.
type FlowKind string

const (
	// KindLogin signs a user in and starts a session.
	KindLogin FlowKind = "login"
	// KindStepUp checks the password of a signed-in user again and renews the auth time of the session.
	// Only a factor of LoginFlow.UserID counts.
	KindStepUp FlowKind = "step_up"
)

// ParseFlowKind reads a stored kind.
func ParseFlowKind(raw string) (FlowKind, error) {
	switch kind := FlowKind(raw); kind {
	case KindLogin, KindStepUp:
		return kind, nil
	default:
		return "", fmt.Errorf("loginflow: flow kind %q", raw)
	}
}
