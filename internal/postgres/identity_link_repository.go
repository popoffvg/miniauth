package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

// IdentityLinkRepository is the PostgreSQL adapter for pending identity links.
type IdentityLinkRepository struct {
	q *sqlcgen.Queries
}

// NewIdentityLinkRepository returns a repository that uses db for queries.
func NewIdentityLinkRepository(db sqlcgen.DBTX) *IdentityLinkRepository {
	return &IdentityLinkRepository{q: sqlcgen.New(db)}
}

var _ identitylink.Store = (*IdentityLinkRepository)(nil)

// Insert stores the pending link under the hash of the browser secret.
func (r *IdentityLinkRepository) Insert(ctx context.Context, hash identitylink.SecretHash, link identitylink.PendingLink) error {
	err := r.q.InsertPendingIdentityLink(ctx, sqlcgen.InsertPendingIdentityLinkParams{
		SecretHash: hash[:],
		Provider:   link.Account.Kind.String(),
		Subject:    link.Account.Subject.String(),
		CreatedAt:  pgTime(link.CreatedAt),
		ExpiresAt:  pgTime(link.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("postgres: insert pending identity link: %w", err)
	}
	return nil
}

// Link deletes the live pending link and inserts the identity in one statement, so both happen or neither.
func (r *IdentityLinkRepository) Link(ctx context.Context, hash identitylink.SecretHash, userID users.ID, identityID users.IdentityID, now time.Time) (users.ExternalAccount, error) {
	row, err := r.q.LinkPendingIdentity(ctx, sqlcgen.LinkPendingIdentityParams{
		IdentityID: pgUUIDBytes(identityID.Bytes()),
		UserID:     pgUUIDBytes(userID.Bytes()),
		Now:        pgTime(now),
		SecretHash: hash[:],
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return users.ExternalAccount{}, identitylink.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		if deleteErr := r.q.DeletePendingIdentityLink(ctx, hash[:]); deleteErr != nil {
			return users.ExternalAccount{}, fmt.Errorf("postgres: delete pending identity link: %w", deleteErr)
		}
		return users.ExternalAccount{}, identitylink.ErrAccountTaken
	}
	if err != nil {
		return users.ExternalAccount{}, fmt.Errorf("postgres: link pending identity: %w", err)
	}
	subject, err := users.ParseSubject(row.Subject)
	if err != nil {
		return users.ExternalAccount{}, fmt.Errorf("postgres: link pending identity: %w", err)
	}
	return users.ExternalAccount{Kind: users.Kind(row.Kind), Subject: subject}, nil
}

// Cleanup deletes the pending links that expired at or before now.
func (r *IdentityLinkRepository) Cleanup(ctx context.Context, now time.Time) error {
	if err := r.q.DeleteExpiredPendingIdentityLinks(ctx, pgTime(now)); err != nil {
		return fmt.Errorf("postgres: cleanup pending identity links: %w", err)
	}
	return nil
}
