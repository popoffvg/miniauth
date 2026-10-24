package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/user"
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

var _ user.Repository = (*UserRepository)(nil)

// Create inserts the user and the password identity in one statement.
// A login that is already stored returns user.ErrLoginTaken.
func (r *UserRepository) Create(ctx context.Context, account user.User, identity user.Identity) error {
	if identity.Kind != user.KindPassword {
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

func createUserError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "users_login_unique" {
			return user.ErrLoginTaken
		}
		return fmt.Errorf("postgres: create user: %s (SQLSTATE %s)", pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: create user: %w", err)
}

func pgUUIDBytes(b [16]byte) pgtype.UUID {
	return pgtype.UUID{Bytes: b, Valid: true}
}
