package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

// AccessRepository is the PostgreSQL adapter for resources and grants.
type AccessRepository struct {
	q *sqlcgen.Queries
}

// NewAccessRepository refuses a nil database before any query runs.
func NewAccessRepository(db sqlcgen.DBTX) (*AccessRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: access repository database is missing")
	}
	return &AccessRepository{q: sqlcgen.New(db)}, nil
}

var _ access.Repository = (*AccessRepository)(nil)

// CreateResource returns access.ErrDuplicateResource when the name or the URL is stored.
func (r *AccessRepository) CreateResource(ctx context.Context, resource access.Resource) error {
	err := r.q.InsertResource(ctx, sqlcgen.InsertResourceParams{
		Name:       resource.Name.String(),
		Host:       resource.URL.Host.String(),
		PathPrefix: resource.URL.Prefix.String(),
	})
	if err != nil {
		return accessError("create resource", err)
	}
	return nil
}

// DeleteResource deletes the resource. The grants go with it.
func (r *AccessRepository) DeleteResource(ctx context.Context, name access.ResourceName) error {
	n, err := r.q.DeleteResource(ctx, name.String())
	if err != nil {
		return accessError("delete resource", err)
	}
	if n == 0 {
		return access.ErrResourceNotFound
	}
	return nil
}

// FindResource returns access.ErrResourceNotFound for a missing name.
func (r *AccessRepository) FindResource(ctx context.Context, name access.ResourceName) (access.Resource, error) {
	row, err := r.q.GetResource(ctx, name.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return access.Resource{}, access.ErrResourceNotFound
	}
	if err != nil {
		return access.Resource{}, accessError("find resource", err)
	}
	return resourceFromRow(row)
}

// ListResources returns the resources on host in name order.
func (r *AccessRepository) ListResources(ctx context.Context, host access.Host) ([]access.Resource, error) {
	rows, err := r.q.ListResourcesByHost(ctx, host.String())
	if err != nil {
		return nil, accessError("list resources", err)
	}
	resources := make([]access.Resource, 0, len(rows))
	for _, row := range rows {
		resource, err := resourceFromRow(row)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

// CreateGrant returns access.ErrResourceNotFound, access.ErrUnknownUser, or access.ErrDuplicateGrant.
func (r *AccessRepository) CreateGrant(ctx context.Context, grant access.Grant) error {
	params := sqlcgen.InsertAccessGrantParams{
		ID:           pgUUIDBytes(grant.ID.Bytes()),
		ResourceName: grant.Resource.String(),
		CreatedAt:    pgTime(grant.CreatedAt),
	}
	if id, ok := grant.Subject.User(); ok {
		params.UserID = pgUUIDBytes(id.Bytes())
	}
	if name, ok := grant.Subject.Group(); ok {
		params.GroupName = pgtype.Text{String: name.String(), Valid: true}
	}
	if at, ok := grant.Expiry.Time(); ok {
		params.ExpiresAt = pgTime(at)
	}
	if err := r.q.InsertAccessGrant(ctx, params); err != nil {
		return accessError("create grant", err)
	}
	return nil
}

// DeleteGrant returns access.ErrGrantNotFound for a missing id.
func (r *AccessRepository) DeleteGrant(ctx context.Context, id access.GrantID) error {
	n, err := r.q.DeleteAccessGrant(ctx, pgUUIDBytes(id.Bytes()))
	if err != nil {
		return accessError("delete grant", err)
	}
	if n == 0 {
		return access.ErrGrantNotFound
	}
	return nil
}

// ListGrants returns every grant of the resource, oldest first.
func (r *AccessRepository) ListGrants(ctx context.Context, resource access.ResourceName) ([]access.Grant, error) {
	rows, err := r.q.ListAccessGrants(ctx, resource.String())
	if err != nil {
		return nil, accessError("list grants", err)
	}
	grants := make([]access.Grant, 0, len(rows))
	for _, row := range rows {
		grant, err := grantFromRow(row)
		if err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, nil
}

// ListAllResources returns every resource in name order.
func (r *AccessRepository) ListAllResources(ctx context.Context) ([]access.Resource, error) {
	rows, err := r.q.ListAllResources(ctx)
	if err != nil {
		return nil, accessError("list all resources", err)
	}
	resources := make([]access.Resource, 0, len(rows))
	for _, row := range rows {
		resource, err := resourceFromRow(row)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

// ListGrantEntries returns the grants that match filter, in resource name order and then oldest first.
func (r *AccessRepository) ListGrantEntries(ctx context.Context, filter access.GrantFilter) ([]access.GrantEntry, error) {
	var params sqlcgen.ListAccessGrantEntriesParams
	if filter.User != (users.Login{}) {
		params.Login = pgtype.Text{String: filter.User.String(), Valid: true}
	}
	if filter.Resource != (access.ResourceName{}) {
		params.ResourceName = pgtype.Text{String: filter.Resource.String(), Valid: true}
	}
	rows, err := r.q.ListAccessGrantEntries(ctx, params)
	if err != nil {
		return nil, accessError("list grant entries", err)
	}
	entries := make([]access.GrantEntry, 0, len(rows))
	for _, row := range rows {
		entry, err := grantEntryFromRow(row)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func grantEntryFromRow(row sqlcgen.ListAccessGrantEntriesRow) (access.GrantEntry, error) {
	grant, err := grantFromRow(sqlcgen.AccessGrant{
		ID:           row.ID,
		ResourceName: row.ResourceName,
		UserID:       row.UserID,
		GroupName:    row.GroupName,
		ExpiresAt:    row.ExpiresAt,
		CreatedAt:    row.CreatedAt,
	})
	if err != nil {
		return access.GrantEntry{}, err
	}
	resource, err := resourceFromRow(sqlcgen.Resource{Name: row.ResourceName, Host: row.Host, PathPrefix: row.PathPrefix})
	if err != nil {
		return access.GrantEntry{}, err
	}
	var login users.Login
	if row.UserLogin.Valid {
		login, err = users.ParseLogin(row.UserLogin.String)
		if err != nil {
			return access.GrantEntry{}, fmt.Errorf("postgres: grant row: %w", err)
		}
	}
	return access.GrantEntry{Grant: grant, URL: resource.URL, UserLogin: login}, nil
}

func resourceFromRow(row sqlcgen.Resource) (access.Resource, error) {
	name, err := access.ParseResourceName(row.Name)
	if err != nil {
		return access.Resource{}, fmt.Errorf("postgres: resource row: %w", err)
	}
	host, err := access.ParseHost(row.Host)
	if err != nil {
		return access.Resource{}, fmt.Errorf("postgres: resource row: %w", err)
	}
	prefix, err := access.ParsePathPrefix(row.PathPrefix)
	if err != nil {
		return access.Resource{}, fmt.Errorf("postgres: resource row: %w", err)
	}
	return access.Resource{Name: name, URL: access.ResourceURL{Host: host, Prefix: prefix}}, nil
}

func grantFromRow(row sqlcgen.AccessGrant) (access.Grant, error) {
	if !row.ID.Valid || !row.CreatedAt.Valid {
		return access.Grant{}, errors.New("postgres: grant row is incomplete")
	}
	resource, err := access.ParseResourceName(row.ResourceName)
	if err != nil {
		return access.Grant{}, fmt.Errorf("postgres: grant row: %w", err)
	}
	var subject access.Subject
	switch {
	case row.UserID.Valid && !row.GroupName.Valid:
		subject = access.UserSubject(users.IDFromBytes(row.UserID.Bytes))
	case row.GroupName.Valid && !row.UserID.Valid:
		name, err := groups.ParseName(row.GroupName.String)
		if err != nil {
			return access.Grant{}, fmt.Errorf("postgres: grant row: %w", err)
		}
		subject = access.GroupSubject(name)
	default:
		return access.Grant{}, errors.New("postgres: grant row has no single subject")
	}
	var expiry access.Expiry
	if row.ExpiresAt.Valid {
		expiry = access.ExpiresAt(row.ExpiresAt.Time)
	}
	return access.Grant{
		ID:        access.GrantIDFromBytes(row.ID.Bytes),
		Resource:  resource,
		Subject:   subject,
		Expiry:    expiry,
		CreatedAt: row.CreatedAt.Time.UTC(),
	}, nil
}

func accessError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == pgUniqueViolation && (pgErr.ConstraintName == "resources_pkey" || pgErr.ConstraintName == "resources_url_unique"):
			return access.ErrDuplicateResource
		case pgErr.Code == pgUniqueViolation && (pgErr.ConstraintName == "access_grants_user_unique" || pgErr.ConstraintName == "access_grants_group_unique"):
			return access.ErrDuplicateGrant
		case pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "access_grants_resource_name_fkey":
			return access.ErrResourceNotFound
		case pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "access_grants_user_id_fkey":
			return access.ErrUnknownUser
		default:
			return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
		}
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
