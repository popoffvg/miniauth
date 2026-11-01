package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/users"
)

// PostgreSQL unique_violation. The message and the detail are not returned:
// a check failure can echo the row, and the row holds the password hash.
const pgUniqueViolation = "23505"

// UserRepository is the PostgreSQL adapter for users and password identities.
type UserRepository struct {
	q *sqlcgen.Queries
}

// NewUserRepository returns a repository that uses db for queries.
func NewUserRepository(db sqlcgen.DBTX) *UserRepository {
	return &UserRepository{q: sqlcgen.New(db)}
}

var (
	_ users.Repository       = (*UserRepository)(nil)
	_ password.IdentityStore = (*UserRepository)(nil)
)

// Create inserts the user and the password identity in one statement.
// A login that is already stored returns users.ErrLoginTaken.
func (r *UserRepository) Create(ctx context.Context, account users.User, identity users.Identity) error {
	if identity.Kind != users.KindPassword {
		return fmt.Errorf("postgres: identity kind %q", identity.Kind)
	}
	if identity.UserID != account.ID {
		return errors.New("postgres: identity user does not match")
	}
	encoded := identity.Secret.Encoded()
	if encoded == "" {
		return errors.New("postgres: password hash is empty")
	}
	err := r.q.InsertUserIdentity(ctx, sqlcgen.InsertUserIdentityParams{
		UserID:       pgUUIDBytes(account.ID.Bytes()),
		Login:        account.Login.String(),
		CreatedAt:    pgTime(account.CreatedAt),
		IdentityID:   pgUUIDBytes(identity.ID.Bytes()),
		Kind:         identity.Kind.String(),
		PasswordHash: pgtype.Text{String: encoded, Valid: true},
	})
	if err != nil {
		return createUserError(err)
	}
	return nil
}

// Find returns the user with id.
// A missing id is users.ErrNotFound.
func (r *UserRepository) Find(ctx context.Context, id users.ID) (users.User, error) {
	return userFromRow(r.q.GetUserByID(ctx, pgUUIDBytes(id.Bytes())))
}

// FindByLogin returns the user with login, a disabled user included.
// A missing login is users.ErrNotFound.
func (r *UserRepository) FindByLogin(ctx context.Context, login users.Login) (users.User, error) {
	return userFromRow(r.q.GetUserByLogin(ctx, login.String()))
}

func userFromRow(stored sqlcgen.User, err error) (users.User, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return users.User{}, users.ErrNotFound
	}
	if err != nil {
		return users.User{}, fmt.Errorf("postgres: load user: %w", err)
	}
	if !stored.ID.Valid || !stored.CreatedAt.Valid {
		return users.User{}, errors.New("postgres: stored user is incomplete")
	}
	login, err := users.ParseLogin(stored.Login)
	if err != nil {
		return users.User{}, fmt.Errorf("postgres: load user: %w", err)
	}
	return users.User{
		ID:         users.IDFromBytes(stored.ID.Bytes),
		Login:      login,
		CreatedAt:  stored.CreatedAt.Time.UTC(),
		DisabledAt: optionalTime(stored.DisabledAt),
	}, nil
}

// FindPasswordIdentity returns the password identity of login.
// A login that is not stored is users.ErrNotFound.
func (r *UserRepository) FindPasswordIdentity(ctx context.Context, login users.Login) (users.Identity, error) {
	stored, err := r.q.GetIdentityByLogin(ctx, login.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return users.Identity{}, users.ErrNotFound
	}
	if err != nil {
		return users.Identity{}, fmt.Errorf("postgres: load identity: %w", err)
	}
	if !stored.UserID.Valid || !stored.IdentityID.Valid || !stored.IdentityCreatedAt.Valid {
		return users.Identity{}, errors.New("postgres: stored identity is incomplete")
	}
	// The parse error does not wrap the PHC string, so it is safe to return.
	hash, err := users.ParsePasswordHash(stored.PasswordHash.String)
	if err != nil {
		return users.Identity{}, fmt.Errorf("postgres: load identity: %w", err)
	}
	return users.Identity{
		ID:        users.IdentityIDFromBytes(stored.IdentityID.Bytes),
		UserID:    users.IDFromBytes(stored.UserID.Bytes),
		Kind:      users.Kind(stored.Kind),
		Secret:    hash,
		CreatedAt: stored.IdentityCreatedAt.Time.UTC(),
	}, nil
}

// Disable sets disabled_at once. A later call keeps the first time.
// A missing id is users.ErrNotFound.
func (r *UserRepository) Disable(ctx context.Context, id users.ID, at time.Time) error {
	n, err := r.q.DisableUser(ctx, sqlcgen.DisableUserParams{
		DisabledAt: pgTime(at),
		ID:         pgUUIDBytes(id.Bytes()),
	})
	if err != nil {
		return fmt.Errorf("postgres: disable user: %w", err)
	}
	if n == 0 {
		return users.ErrNotFound
	}
	return nil
}

func createUserError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "users_login_unique" {
			return users.ErrLoginTaken
		}
		return fmt.Errorf("postgres: create user: %s (SQLSTATE %s)", pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: create user: %w", err)
}

func pgUUIDBytes(b [16]byte) pgtype.UUID {
	return pgtype.UUID{Bytes: b, Valid: true}
}
