package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

// GroupRepository is the PostgreSQL adapter for group membership.
type GroupRepository struct {
	q *sqlcgen.Queries
}

// NewGroupRepository returns a repository that uses db for queries.
func NewGroupRepository(db sqlcgen.DBTX) *GroupRepository {
	return &GroupRepository{q: sqlcgen.New(db)}
}

var _ groups.Repository = (*GroupRepository)(nil)

// List returns the groups of userID in ascending name order.
func (r *GroupRepository) List(ctx context.Context, userID users.ID) ([]groups.Name, error) {
	rows, err := r.q.ListGroupMemberships(ctx, pgUUIDBytes(userID.Bytes()))
	if err != nil {
		return nil, groupError("list groups", err)
	}
	names := make([]groups.Name, 0, len(rows))
	for _, row := range rows {
		name, err := groups.ParseName(row)
		if err != nil {
			return nil, fmt.Errorf("postgres: list groups: %w", err)
		}
		names = append(names, name)
	}
	return names, nil
}

// Add stores one membership.
// A second add of the same pair returns groups.ErrDuplicate.
// An unknown user returns groups.ErrUnknownUser.
func (r *GroupRepository) Add(ctx context.Context, userID users.ID, name groups.Name) error {
	if name.String() == "" {
		return groups.ErrName
	}
	err := r.q.InsertGroupMembership(ctx, sqlcgen.InsertGroupMembershipParams{
		UserID: pgUUIDBytes(userID.Bytes()),
		Name:   name.String(),
	})
	if err != nil {
		return groupError("add group", err)
	}
	return nil
}

func groupError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "group_memberships_pkey":
			return groups.ErrDuplicate
		case pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "group_memberships_user_id_fkey":
			return groups.ErrUnknownUser
		default:
			return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
		}
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
