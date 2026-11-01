package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/users"
)

// PasskeyRepository is the PostgreSQL adapter for passkeys.
type PasskeyRepository struct {
	q *sqlcgen.Queries
}

// NewPasskeyRepository returns a repository that uses db for queries.
func NewPasskeyRepository(db sqlcgen.DBTX) *PasskeyRepository {
	return &PasskeyRepository{q: sqlcgen.New(db)}
}

var _ passkey.Store = (*PasskeyRepository)(nil)

// Create inserts the passkey.
func (r *PasskeyRepository) Create(ctx context.Context, passkeyRow passkey.Passkey) error {
	transports := make([]string, 0, len(passkeyRow.Transports))
	for _, transport := range passkeyRow.Transports {
		transports = append(transports, string(transport))
	}
	err := r.q.InsertPasskey(ctx, sqlcgen.InsertPasskeyParams{
		ID:             pgUUIDBytes(passkeyRow.ID.Bytes()),
		UserID:         pgUUIDBytes(passkeyRow.UserID.Bytes()),
		CredentialID:   passkeyRow.CredentialID,
		PublicKey:      passkeyRow.PublicKey,
		SignCount:      int64(passkeyRow.SignCount),
		Transports:     transports,
		Aaguid:         pgUUIDBytes(passkeyRow.AAGUID),
		BackupEligible: passkeyRow.BackupEligible,
		Name:           passkeyRow.Name.String(),
		CreatedAt:      pgTime(passkeyRow.CreatedAt),
	})
	if err != nil {
		return passkeyError("create passkey", err)
	}
	return nil
}

// FindByCredential returns the passkey with the credential id when its user is active.
func (r *PasskeyRepository) FindByCredential(ctx context.Context, id passkey.CredentialID) (passkey.Passkey, error) {
	row, err := r.q.GetActivePasskeyByCredential(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return passkey.Passkey{}, passkey.ErrUnknownCredential
	}
	if err != nil {
		return passkey.Passkey{}, passkeyError("load passkey", err)
	}
	return passkeyFromRow(row)
}

// List returns the passkeys of userID, oldest first.
func (r *PasskeyRepository) List(ctx context.Context, userID users.ID) ([]passkey.Passkey, error) {
	rows, err := r.q.ListUserPasskeys(ctx, pgUUIDBytes(userID.Bytes()))
	if err != nil {
		return nil, passkeyError("list passkeys", err)
	}
	out := make([]passkey.Passkey, 0, len(rows))
	for _, row := range rows {
		passkeyRow, err := passkeyFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, passkeyRow)
	}
	return out, nil
}

// RecordUse writes the counter and the time of use while the stored counter is still prev.
func (r *PasskeyRepository) RecordUse(ctx context.Context, id passkey.ID, prev, next passkey.SignCount, at time.Time) (bool, error) {
	n, err := r.q.RecordPasskeyUse(ctx, sqlcgen.RecordPasskeyUseParams{
		NextCount: int64(next),
		UsedAt:    pgTime(at),
		ID:        pgUUIDBytes(id.Bytes()),
		PrevCount: int64(prev),
	})
	if err != nil {
		return false, passkeyError("record passkey use", err)
	}
	return n == 1, nil
}

// Delete removes one passkey of userID.
func (r *PasskeyRepository) Delete(ctx context.Context, userID users.ID, id passkey.ID) error {
	n, err := r.q.DeleteUserPasskey(ctx, sqlcgen.DeleteUserPasskeyParams{
		ID:     pgUUIDBytes(id.Bytes()),
		UserID: pgUUIDBytes(userID.Bytes()),
	})
	if err != nil {
		return passkeyError("delete passkey", err)
	}
	if n == 0 {
		return passkey.ErrNotFound
	}
	return nil
}

func passkeyFromRow(row sqlcgen.Passkey) (passkey.Passkey, error) {
	if !row.ID.Valid || !row.UserID.Valid || !row.Aaguid.Valid || !row.CreatedAt.Valid {
		return passkey.Passkey{}, errors.New("postgres: passkey row is incomplete")
	}
	if row.SignCount < 0 || row.SignCount > int64(^uint32(0)) {
		return passkey.Passkey{}, fmt.Errorf("postgres: passkey sign count %d", row.SignCount)
	}
	name, err := passkey.ParseName(row.Name)
	if err != nil {
		return passkey.Passkey{}, fmt.Errorf("postgres: load passkey: %w", err)
	}
	transports := make([]passkey.Transport, 0, len(row.Transports))
	for _, transport := range row.Transports {
		transports = append(transports, passkey.Transport(transport))
	}
	return passkey.Passkey{
		ID:             passkey.IDFromBytes(row.ID.Bytes),
		UserID:         users.IDFromBytes(row.UserID.Bytes),
		CredentialID:   row.CredentialID,
		PublicKey:      row.PublicKey,
		SignCount:      passkey.SignCount(row.SignCount),
		Transports:     transports,
		AAGUID:         row.Aaguid.Bytes,
		BackupEligible: row.BackupEligible,
		Name:           name,
		CreatedAt:      row.CreatedAt.Time.UTC(),
		LastUsedAt:     optionalTime(row.LastUsedAt),
	}, nil
}

// passkeyError does not return the PostgreSQL message: a constraint failure can echo the row.
func passkeyError(action string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "passkeys_credential_id_unique" {
			return passkey.ErrDuplicate
		}
		return fmt.Errorf("postgres: %s: %s (SQLSTATE %s)", action, pgErr.ConstraintName, pgErr.Code)
	}
	return fmt.Errorf("postgres: %s: %w", action, err)
}
