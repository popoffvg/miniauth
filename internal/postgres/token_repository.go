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
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// TokenRepository is the PostgreSQL adapter for personal access tokens.
type TokenRepository struct {
	q *sqlcgen.Queries
}

// NewTokenRepository returns a repository that uses db for queries.
func NewTokenRepository(db sqlcgen.DBTX) *TokenRepository {
	return &TokenRepository{q: sqlcgen.New(db)}
}

var _ tokens.Repository = (*TokenRepository)(nil)

// Create inserts the token hash.
func (r *TokenRepository) Create(ctx context.Context, token tokens.Token, hash tokens.Hash) error {
	err := r.q.InsertAccessToken(ctx, sqlcgen.InsertAccessTokenParams{
		ID:            pgUUIDBytes(token.ID.Bytes()),
		UserID:        pgUUIDBytes(token.UserID.Bytes()),
		SecretHash:    hash[:],
		DisplayPrefix: token.Prefix.String(),
		Name:          token.Name.String(),
		Scopes:        token.Scopes.Strings(),
		CreatedAt:     pgTime(token.CreatedAt),
		ExpiresAt:     pgOptionalTime(token.ExpiresAt),
	})
	if err != nil {
		return tokenError("create token", err)
	}
	return nil
}

// Find returns the token stored under hash.
// The returned hash is the column value, so the caller can compare it in constant time.
func (r *TokenRepository) Find(ctx context.Context, hash tokens.Hash) (tokens.Token, tokens.Hash, error) {
	row, err := r.q.GetAccessTokenByHash(ctx, hash[:])
	if errors.Is(err, pgx.ErrNoRows) {
		return tokens.Token{}, tokens.Hash{}, tokens.ErrInvalid
	}
	if err != nil {
		return tokens.Token{}, tokens.Hash{}, tokenError("load token", err)
	}
	return tokenFromRow(row)
}

// List returns the tokens of userID, oldest first.
func (r *TokenRepository) List(ctx context.Context, userID users.ID) ([]tokens.Token, error) {
	rows, err := r.q.ListUserAccessTokens(ctx, pgUUIDBytes(userID.Bytes()))
	if err != nil {
		return nil, tokenError("list tokens", err)
	}
	out := make([]tokens.Token, 0, len(rows))
	for _, row := range rows {
		token, _, err := tokenFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, token)
	}
	return out, nil
}

// Revoke sets revoked_at once. A later call keeps the first time.
func (r *TokenRepository) Revoke(ctx context.Context, userID users.ID, id tokens.ID, at time.Time) error {
	n, err := r.q.RevokeAccessToken(ctx, sqlcgen.RevokeAccessTokenParams{
		RevokedAt: pgTime(at),
		ID:        pgUUIDBytes(id.Bytes()),
		UserID:    pgUUIDBytes(userID.Bytes()),
	})
	if err != nil {
		return tokenError("revoke token", err)
	}
	if n == 0 {
		return tokens.ErrNotFound
	}
	return nil
}

// Touch writes last_used_at when the stored value is empty or at or before touchBefore.
func (r *TokenRepository) Touch(ctx context.Context, id tokens.ID, at, touchBefore time.Time) error {
	err := r.q.TouchAccessToken(ctx, sqlcgen.TouchAccessTokenParams{
		LastUsedAt:  pgTime(at),
		ID:          pgUUIDBytes(id.Bytes()),
		TouchBefore: pgTime(touchBefore),
	})
	if err != nil {
		return tokenError("touch token", err)
	}
	return nil
}

func tokenFromRow(row sqlcgen.AccessToken) (tokens.Token, tokens.Hash, error) {
	if !row.ID.Valid || !row.UserID.Valid || !row.CreatedAt.Valid {
		return tokens.Token{}, tokens.Hash{}, errors.New("postgres: token row is incomplete")
	}
	var hash tokens.Hash
	if len(row.SecretHash) != len(hash) {
		return tokens.Token{}, tokens.Hash{}, fmt.Errorf("postgres: token hash length %d", len(row.SecretHash))
	}
	copy(hash[:], row.SecretHash)
	prefix, err := tokens.ParsePrefix(row.DisplayPrefix)
	if err != nil {
		return tokens.Token{}, tokens.Hash{}, fmt.Errorf("postgres: load token: %w", err)
	}
	name, err := tokens.ParseName(row.Name)
	if err != nil {
		return tokens.Token{}, tokens.Hash{}, fmt.Errorf("postgres: load token: %w", err)
	}
	scopes, err := tokens.ParseScopes(row.Scopes)
	if err != nil {
		return tokens.Token{}, tokens.Hash{}, fmt.Errorf("postgres: load token: %w", err)
	}
	return tokens.Token{
		ID:         tokens.IDFromBytes(row.ID.Bytes),
		UserID:     users.IDFromBytes(row.UserID.Bytes),
		Prefix:     prefix,
		Name:       name,
		Scopes:     scopes,
		CreatedAt:  row.CreatedAt.Time.UTC(),
		ExpiresAt:  optionalTime(row.ExpiresAt),
		RevokedAt:  optionalTime(row.RevokedAt),
		LastUsedAt: optionalTime(row.LastUsedAt),
	}, hash, nil
}

// pgOptionalTime stores a zero time as NULL.
func pgOptionalTime(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgTime(t)
}

// optionalTime reads NULL as the zero time.
func optionalTime(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}

// tokenError does not return the PostgreSQL message: a constraint failure can echo the row.
func tokenError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch {
		case pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "access_tokens_secret_hash_unique":
			return tokens.ErrDuplicate
		case pgErr.Code == pgForeignKeyViolation && pgErr.ConstraintName == "access_tokens_user_id_fkey":
			return tokens.ErrUnknownUser
		}
		return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
