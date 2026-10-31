package googlestep

import "errors"

var (
	// ErrUnavailable means provider discovery has not succeeded, or failed on the last try.
	ErrUnavailable = errors.New("googlestep: Google is not available")
	// ErrBadCallback means the state, the verifier, or the code does not belong to this flow.
	ErrBadCallback = errors.New("googlestep: callback does not match the flow")
	// ErrBadToken means the ID token failed a check: signature, issuer, audience, expiry, or nonce.
	ErrBadToken = errors.New("googlestep: ID token is not valid")
	// ErrConfig means a required config value is empty.
	ErrConfig = errors.New("googlestep: config is not complete")
)
