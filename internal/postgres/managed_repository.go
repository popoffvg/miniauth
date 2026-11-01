package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

// ManagedRepository is the PostgreSQL adapter for the rows that the resources file owns.
type ManagedRepository struct {
	db transactionalDB
}

// NewManagedRepository refuses a nil database before any query runs.
func NewManagedRepository(db transactionalDB) (*ManagedRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: managed repository database is missing")
	}
	return &ManagedRepository{db: db}, nil
}

var _ access.ManagedStore = (*ManagedRepository)(nil)

// InTransaction commits when fn returns nil and rolls back otherwise.
// The URL check waits for the commit, so two managed resources can swap their URLs.
func (r *ManagedRepository) InTransaction(ctx context.Context, fn func(access.ManagedWriter) error) error {
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		q := sqlcgen.New(tx)
		if err := q.DeferConstraints(ctx); err != nil {
			return accessError("defer the URL check", err)
		}
		return fn(&managedWriter{q: q})
	})
	if err != nil {
		return accessError("reconcile resources", err)
	}
	return nil
}

type managedWriter struct {
	q *sqlcgen.Queries
}

func (w *managedWriter) DeleteStaleGrants(ctx context.Context, keep []access.GroupGrantKey) error {
	params := sqlcgen.DeleteStaleManagedGrantsParams{
		KeepResources: make([]string, 0, len(keep)),
		KeepGroups:    make([]string, 0, len(keep)),
	}
	for _, key := range keep {
		params.KeepResources = append(params.KeepResources, key.Resource.String())
		params.KeepGroups = append(params.KeepGroups, key.Group.String())
	}
	if _, err := w.q.DeleteStaleManagedGrants(ctx, params); err != nil {
		return accessError("delete stale managed grants", err)
	}
	return nil
}

func (w *managedWriter) DeleteStaleResources(ctx context.Context, keep []access.ResourceName) error {
	names := make([]string, 0, len(keep))
	for _, name := range keep {
		names = append(names, name.String())
	}
	if _, err := w.q.DeleteStaleManagedResources(ctx, names); err != nil {
		return accessError("delete stale managed resources", err)
	}
	return nil
}

func (w *managedWriter) EnsureGroup(ctx context.Context, name groups.Name, at time.Time) error {
	if err := w.q.EnsureGroup(ctx, sqlcgen.EnsureGroupParams{Name: name.String(), CreatedAt: pgTime(at)}); err != nil {
		return groupError("ensure group", err)
	}
	return nil
}

// PutManagedResource checks an unmanaged URL itself: the deferred URL check fails only at the commit.
func (w *managedWriter) PutManagedResource(ctx context.Context, resource access.Resource) error {
	taken, err := w.q.UnmanagedResourceHasURL(ctx, sqlcgen.UnmanagedResourceHasURLParams{
		Host:       resource.URL.Host.String(),
		PathPrefix: resource.URL.Prefix.String(),
		Name:       resource.Name.String(),
	})
	if err != nil {
		return accessError("find unmanaged resource", err)
	}
	if taken {
		return access.ErrDuplicateResource
	}
	err = w.q.UpsertManagedResource(ctx, sqlcgen.UpsertManagedResourceParams{
		Name:       resource.Name.String(),
		Host:       resource.URL.Host.String(),
		PathPrefix: resource.URL.Prefix.String(),
	})
	if err != nil {
		return accessError("put managed resource", err)
	}
	return nil
}

func (w *managedWriter) PutManagedGrant(ctx context.Context, grant access.Grant) error {
	name, ok := grant.Subject.Group()
	if !ok {
		return access.ErrSubject
	}
	err := w.q.UpsertManagedGroupGrant(ctx, sqlcgen.UpsertManagedGroupGrantParams{
		ID:           pgUUIDBytes(grant.ID.Bytes()),
		ResourceName: grant.Resource.String(),
		GroupName:    pgtype.Text{String: name.String(), Valid: true},
		CreatedAt:    pgTime(grant.CreatedAt),
	})
	if err != nil {
		return accessError("put managed grant", err)
	}
	return nil
}
