package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
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

var _ users.Repository = (*UserRepository)(nil)

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
		PasswordHash: encoded,
	})
	if err != nil {
		return createUserError(err)
	}
	return nil
}

// Find returns the user with id.
// A missing id is users.ErrNotFound.
func (r *UserRepository) Find(ctx context.Context, id users.ID) (users.User, error) {
	stored, err := r.q.GetUserByID(ctx, pgUUIDBytes(id.Bytes()))
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
		ID:        users.IDFromBytes(stored.ID.Bytes),
		Login:     login,
		CreatedAt: stored.CreatedAt.Time.UTC(),
	}, nil
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
