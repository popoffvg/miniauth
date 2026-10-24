package loginflow

import "errors"

var (
	// ErrFlowNotFound means the flow is missing, expired, or the secret does not match.
	ErrFlowNotFound = errors.New("loginflow: flow not found")
	// ErrNoTransition means the policy refuses the event in the current state.
	ErrNoTransition = errors.New("loginflow: no transition")
	// ErrReturnURL means the return URL is empty.
	ErrReturnURL = errors.New("loginflow: return URL is empty")
)
