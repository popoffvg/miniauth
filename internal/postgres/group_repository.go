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

// NewGroupRepository refuses a nil database before any query runs.
func NewGroupRepository(db sqlcgen.DBTX) (*GroupRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: group repository database is missing")
	}
	return &GroupRepository{q: sqlcgen.New(db)}, nil
}

var (
	_ groups.Repository = (*GroupRepository)(nil)
	_ groups.Writer     = (*GroupRepository)(nil)
)

// List returns the groups of userID in ascending name order.
func (r *GroupRepository) List(ctx context.Context, userID users.ID) ([]groups.Name, error) {
	rawNames, err := r.q.ListGroupMemberships(ctx, pgUUIDBytes(userID.Bytes()))
	if err != nil {
		return nil, groupError("list groups", err)
	}
	names := make([]groups.Name, 0, len(rawNames))
	for _, rawName := range rawNames {
		name, err := groups.ParseName(rawName)
		if err != nil {
			return nil, fmt.Errorf("postgres: list groups: %w", err)
		}
		names = append(names, name)
	}
	return names, nil
}

// Add returns groups.ErrDuplicate when the pair is already stored.
// An unknown user returns groups.ErrUnknownUser and an unknown group groups.ErrGroupNotFound.
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
		case pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "group_memberships_name_fkey":
			return groups.ErrGroupNotFound
		default:
			return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
		}
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
