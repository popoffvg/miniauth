package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

// transactionalDB runs queries and begins transactions. *pgxpool.Pool is one.
type transactionalDB interface {
	sqlcgen.DBTX
	Begin(ctx context.Context) (pgx.Tx, error)
}

// InviteRepository is the PostgreSQL adapter for invites.
type InviteRepository struct {
	db transactionalDB
	q  *sqlcgen.Queries
}

// NewInviteRepository refuses a nil database before any query runs.
func NewInviteRepository(db transactionalDB) (*InviteRepository, error) {
	if db == nil {
		return nil, errors.New("postgres: invite repository database is missing")
	}
	return &InviteRepository{db: db, q: sqlcgen.New(db)}, nil
}

var _ invites.Store = (*InviteRepository)(nil)

// Create returns groups.ErrGroupNotFound when the group is not stored.
func (r *InviteRepository) Create(ctx context.Context, invite invites.Invite) error {
	err := r.q.InsertInvite(ctx, sqlcgen.InsertInviteParams{
		TokenHash: invite.Hash[:],
		GroupName: invite.Group.String(),
		CreatedAt: pgTime(invite.CreatedAt),
		ExpiresAt: pgTime(invite.ExpiresAt),
	})
	if err != nil {
		return inviteError("create invite", err)
	}
	return nil
}

// Find returns invites.ErrInviteGone for a hash that is not stored.
func (r *InviteRepository) Find(ctx context.Context, hash invites.TokenHash) (invites.Invite, error) {
	row, err := r.q.GetInvite(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return invites.Invite{}, invites.ErrInviteGone
	}
	if err != nil {
		return invites.Invite{}, inviteError("find invite", err)
	}
	return inviteFromRow(row)
}

// InTransaction commits when fn returns nil and rolls back otherwise.
func (r *InviteRepository) InTransaction(ctx context.Context, fn func(invites.Transaction) error) error {
	err := pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		return fn(&inviteTransaction{
			q:          sqlcgen.New(tx),
			users:      NewUserRepository(tx),
			membership: &GroupRepository{q: sqlcgen.New(tx)},
		})
	})
	if err != nil {
		return fmt.Errorf("postgres: accept invite: %w", err)
	}
	return nil
}

type inviteTransaction struct {
	q          *sqlcgen.Queries
	users      *UserRepository
	membership *GroupRepository
}

// Find reads the invite inside the transaction. It takes no lock: Claim is the guard.
func (t *inviteTransaction) Find(ctx context.Context, hash invites.TokenHash) (invites.Invite, error) {
	row, err := t.q.GetInvite(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return invites.Invite{}, invites.ErrInviteGone
	}
	if err != nil {
		return invites.Invite{}, inviteError("find invite", err)
	}
	return inviteFromRow(row)
}

// Claim is one conditional UPDATE. A parallel claim waits for the row lock and then sees used_at set.
func (t *inviteTransaction) Claim(ctx context.Context, hash invites.TokenHash, now time.Time) (invites.Invite, error) {
	row, err := t.q.ClaimInvite(ctx, sqlcgen.ClaimInviteParams{Now: pgTime(now), TokenHash: hash[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		return invites.Invite{}, invites.ErrInviteGone
	}
	if err != nil {
		return invites.Invite{}, inviteError("claim invite", err)
	}
	return inviteFromRow(row)
}

func (t *inviteTransaction) RecordUser(ctx context.Context, hash invites.TokenHash, user users.ID) error {
	n, err := t.q.SetInviteUser(ctx, sqlcgen.SetInviteUserParams{TokenHash: hash[:], UserID: pgUUIDBytes(user.Bytes())})
	if err != nil {
		return inviteError("record invite user", err)
	}
	if n == 0 {
		return invites.ErrInviteGone
	}
	return nil
}

func (t *inviteTransaction) Users() users.Repository {
	return t.users
}

func (t *inviteTransaction) Groups() groups.Writer {
	return t.membership
}

func inviteFromRow(row sqlcgen.Invite) (invites.Invite, error) {
	if len(row.TokenHash) != len(invites.TokenHash{}) || !row.CreatedAt.Valid || !row.ExpiresAt.Valid {
		return invites.Invite{}, errors.New("postgres: invite row is incomplete")
	}
	group, err := groups.ParseName(row.GroupName)
	if err != nil {
		return invites.Invite{}, fmt.Errorf("postgres: invite row: %w", err)
	}
	invite := invites.Invite{
		Hash:      invites.TokenHash(row.TokenHash),
		Group:     group,
		CreatedAt: row.CreatedAt.Time.UTC(),
		ExpiresAt: row.ExpiresAt.Time.UTC(),
		UsedAt:    optionalTime(row.UsedAt),
	}
	if row.UserID.Valid {
		invite.UserID = users.IDFromBytes(row.UserID.Bytes)
	}
	return invite, nil
}

func inviteError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "invites_group_name_fkey" {
			return groups.ErrGroupNotFound
		}
		return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
