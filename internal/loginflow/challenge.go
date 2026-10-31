package loginflow

import (
	"context"
	"errors"
)

// ErrChallengeNotFound means the flow has no challenge: it is missing, expired, or already taken.
var ErrChallengeNotFound = errors.New("loginflow: challenge not found")

// Challenge is what one step keeps between its redirect and its callback.
// The step defines the encoding. It MUST NOT hold a secret in clear: a copy of the database alone
// MUST NOT be enough to finish the step.
type Challenge []byte

// ChallengeStore keeps the challenge of a live flow, next to the flow row.
// SaveChallenge replaces the challenge. A missing or expired flow is ErrFlowNotFound.
// TakeChallenge returns the challenge and clears it in one write, so a callback can use it once.
// It returns ErrChallengeNotFound when there is none.
type ChallengeStore interface {
	SaveChallenge(ctx context.Context, id FlowID, challenge Challenge) error
	TakeChallenge(ctx context.Context, id FlowID) (Challenge, error)
}
