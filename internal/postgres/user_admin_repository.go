package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

// UserAdminRepository is the PostgreSQL adapter for the users admin service.
type UserAdminRepository struct {
	db txStarter
	q  *sqlcgen.Queries
}

// NewUserAdminRepository refuses a nil database before any query runs.
func NewUserAdminRepository(db txStarter) (*UserAdminRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: user admin repository database is missing")
	}
	return &UserAdminRepository{db: db, q: sqlcgen.New(db)}, nil
}

var _ useradmin.Store = (*UserAdminRepository)(nil)

// ListAccounts reads the groups, the device count, and the last device time of each user in one query.
func (r *UserAdminRepository) ListAccounts(ctx context.Context) ([]useradmin.Account, error) {
	rows, err := r.q.ListUserAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("postgres: list user accounts: %w", err)
	}
	accounts := make([]useradmin.Account, 0, len(rows))
	for _, row := range rows {
		user, err := userFromRow(sqlcgen.User{ID: row.ID, Login: row.Login, CreatedAt: row.CreatedAt, DisabledAt: row.DisabledAt}, nil)
		if err != nil {
			return nil, err
		}
		account := useradmin.Account{User: user, Devices: int(row.DeviceCount), LastSeen: optionalTime(row.LastSeen)}
		for _, raw := range row.GroupNames {
			name, err := groups.ParseName(raw)
			if err != nil {
				return nil, fmt.Errorf("postgres: list user accounts: %w", err)
			}
			account.Groups = append(account.Groups, name)
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// Disable keeps the first disabled time of a user that is disabled already.
func (r *UserAdminRepository) Disable(ctx context.Context, id users.ID, at time.Time) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin disable user: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := r.q.WithTx(tx)
	userID := pgUUIDBytes(id.Bytes())
	n, err := q.DisableUser(ctx, sqlcgen.DisableUserParams{ID: userID, DisabledAt: pgTime(at)})
	if err != nil {
		return fmt.Errorf("postgres: disable user: %w", err)
	}
	if n == 0 {
		return useradmin.ErrUserNotFound
	}
	if err = q.DeleteUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("postgres: delete user sessions: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit disable user: %w", err)
	}
	return nil
}

// Enable clears the disabled time. It brings back no session.
func (r *UserAdminRepository) Enable(ctx context.Context, id users.ID) error {
	n, err := r.q.EnableUser(ctx, pgUUIDBytes(id.Bytes()))
	if err != nil {
		return fmt.Errorf("postgres: enable user: %w", err)
	}
	if n == 0 {
		return useradmin.ErrUserNotFound
	}
	return nil
}

// AddMember keeps a stored pair as it is, so a repeated add is not an error. An unknown group is groups.ErrGroupNotFound.
func (r *UserAdminRepository) AddMember(ctx context.Context, id users.ID, name groups.Name) error {
	err := r.q.EnsureGroupMembership(ctx, sqlcgen.EnsureGroupMembershipParams{UserID: pgUUIDBytes(id.Bytes()), Name: name.String()})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "group_memberships_user_id_fkey" {
		return useradmin.ErrUserNotFound
	}
	if err != nil {
		return groupError("ensure group", err)
	}
	return nil
}

// RemoveMember returns useradmin.ErrNotMember when no row is deleted.
func (r *UserAdminRepository) RemoveMember(ctx context.Context, id users.ID, name groups.Name) error {
	n, err := r.q.DeleteGroupMembership(ctx, sqlcgen.DeleteGroupMembershipParams{UserID: pgUUIDBytes(id.Bytes()), Name: name.String()})
	if err != nil {
		return groupError("remove group", err)
	}
	if n == 0 {
		return useradmin.ErrNotMember
	}
	return nil
}
