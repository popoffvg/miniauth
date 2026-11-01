package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

// GroupAdminRepository is the PostgreSQL adapter for the groups admin service.
type GroupAdminRepository struct {
	q *sqlcgen.Queries
}

// NewGroupAdminRepository refuses a nil database before any query runs.
func NewGroupAdminRepository(db sqlcgen.DBTX) (*GroupAdminRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: group admin repository database is missing")
	}
	return &GroupAdminRepository{q: sqlcgen.New(db)}, nil
}

var _ groupadmin.Store = (*GroupAdminRepository)(nil)

// ListGroups reads the member count and the resources of each group in one query.
func (r *GroupAdminRepository) ListGroups(ctx context.Context) ([]groupadmin.Group, error) {
	return r.summaries(ctx, pgtype.Text{})
}

// FindGroup returns groups.ErrGroupNotFound for a name that is not stored.
func (r *GroupAdminRepository) FindGroup(ctx context.Context, name groups.Name) (groupadmin.Group, error) {
	found, err := r.summaries(ctx, pgtype.Text{String: name.String(), Valid: true})
	if err != nil {
		return groupadmin.Group{}, err
	}
	if len(found) == 0 {
		return groupadmin.Group{}, groups.ErrGroupNotFound
	}
	return found[0], nil
}

// CreateGroup returns groups.ErrDuplicateGroup for a name that is stored.
func (r *GroupAdminRepository) CreateGroup(ctx context.Context, name groups.Name, at time.Time) error {
	err := r.q.InsertGroup(ctx, sqlcgen.InsertGroupParams{Name: name.String(), CreatedAt: pgTime(at)})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "groups_pkey" {
		return groups.ErrDuplicateGroup
	}
	if err != nil {
		return groupError("create group", err)
	}
	return nil
}

// DeleteGroup keeps a built-in group: the query deletes no built-in row, and the name then reads as not found.
func (r *GroupAdminRepository) DeleteGroup(ctx context.Context, name groups.Name) error {
	n, err := r.q.DeleteGroup(ctx, name.String())
	if err != nil {
		return groupError("delete group", err)
	}
	if n == 0 {
		return groups.ErrGroupNotFound
	}
	return nil
}

func (r *GroupAdminRepository) summaries(ctx context.Context, name pgtype.Text) ([]groupadmin.Group, error) {
	rows, err := r.q.ListGroupSummaries(ctx, name)
	if err != nil {
		return nil, groupError("list groups", err)
	}
	found := make([]groupadmin.Group, 0, len(rows))
	for _, row := range rows {
		group, err := groupFromSummary(row)
		if err != nil {
			return nil, err
		}
		found = append(found, group)
	}
	return found, nil
}

func groupFromSummary(row sqlcgen.ListGroupSummariesRow) (groupadmin.Group, error) {
	name, err := groups.ParseName(row.Name)
	if err != nil {
		return groupadmin.Group{}, fmt.Errorf("postgres: group row: %w", err)
	}
	if len(row.ResourceNames) != len(row.ResourceManaged) || !row.CreatedAt.Valid {
		return groupadmin.Group{}, errors.New("postgres: group row is incomplete")
	}
	group := groupadmin.Group{
		Name:      name,
		BuiltIn:   row.BuiltIn,
		Members:   int(row.MemberCount),
		CreatedAt: row.CreatedAt.Time.UTC(),
	}
	for i, raw := range row.ResourceNames {
		resource, err := access.ParseResourceName(raw)
		if err != nil {
			return groupadmin.Group{}, fmt.Errorf("postgres: group row: %w", err)
		}
		group.Resources = append(group.Resources, groupadmin.GroupResource{Name: resource, Managed: row.ResourceManaged[i]})
	}
	return group, nil
}
