package groups

import (
	"context"

	"github.com/popoffvg/miniauth/internal/users"
)

// Repository is the read side of membership.
// List returns the groups of one user, in ascending name order.
// List returns an empty slice when the user has no groups.
type Repository interface {
	List(ctx context.Context, userID users.ID) ([]Name, error)
}

// Writer is the side that stores a membership.
// Add MUST return ErrDuplicate when the membership is already stored.
// Add MUST return ErrUnknownUser when the user is not stored and ErrGroupNotFound when the group is not stored.
type Writer interface {
	Add(ctx context.Context, userID users.ID, name Name) error
}
