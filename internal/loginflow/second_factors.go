package loginflow

import (
	"context"
	"fmt"

	"github.com/popoffvg/miniauth/internal/users"
)

// SecondFactors tells whether a user MUST pass a second step after a first factor.
type SecondFactors interface {
	HasSecondFactor(ctx context.Context, userID users.ID) (bool, error)
}

// Passed is the EventStepPassed of factor for the known user userID.
// NeedsSecond comes from secondFactors. A nil secondFactors means no user has a second factor.
func Passed(ctx context.Context, secondFactors SecondFactors, factor Factor, userID users.ID) (Event, error) {
	event := Event{Kind: EventStepPassed, Factor: factor, UserID: userID}
	if secondFactors == nil {
		return event, nil
	}
	needs, err := secondFactors.HasSecondFactor(ctx, userID)
	if err != nil {
		return Event{}, fmt.Errorf("loginflow: second factor: %w", err)
	}
	event.NeedsSecond = needs
	return event, nil
}
