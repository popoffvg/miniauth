package groups

import (
	"context"

	"github.com/popoffvg/miniauth/internal/users"
)

// Repository stores group membership.
// List returns the groups of one user, in ascending name order.
// List returns an empty slice when the user has no groups.
// Add MUST return ErrDuplicate when the membership is already stored.
// Add MUST return ErrUnknownUser when the user is not stored.
type Repository interface {
	List(ctx context.Context, userID users.ID) ([]Name, error)
	Add(ctx context.Context, userID users.ID, name Name) error
}
