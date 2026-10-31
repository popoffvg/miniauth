package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

// FindExternalIdentity returns the identity of account. An unknown account or a disabled user is users.ErrNotFound.
func (r *UserRepository) FindExternalIdentity(ctx context.Context, account users.ExternalAccount) (users.Identity, error) {
	stored, err := r.q.GetExternalIdentity(ctx, sqlcgen.GetExternalIdentityParams{
		Kind:    account.Kind.String(),
		Subject: pgtype.Text{String: account.Subject.String(), Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return users.Identity{}, users.ErrNotFound
	}
	if err != nil {
		return users.Identity{}, fmt.Errorf("postgres: load outside identity: %w", err)
	}
	if !stored.IdentityID.Valid || !stored.UserID.Valid || !stored.CreatedAt.Valid {
		return users.Identity{}, errors.New("postgres: stored identity is incomplete")
	}
	subject, err := users.ParseSubject(stored.Subject.String)
	if err != nil {
		return users.Identity{}, fmt.Errorf("postgres: load outside identity: %w", err)
	}
	return users.Identity{
		ID:        users.IdentityIDFromBytes(stored.IdentityID.Bytes),
		UserID:    users.IDFromBytes(stored.UserID.Bytes),
		Kind:      users.Kind(stored.Kind),
		Subject:   subject,
		CreatedAt: stored.CreatedAt.Time.UTC(),
	}, nil
}
