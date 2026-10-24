package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

// FlowStore is the PostgreSQL adapter for login flows.
type FlowStore struct {
	q *sqlcgen.Queries
}

// NewFlowStore returns a store that uses db for queries.
func NewFlowStore(db sqlcgen.DBTX) *FlowStore {
	return &FlowStore{q: sqlcgen.New(db)}
}

var (
	_ loginflow.Store                                   = (*FlowStore)(nil)
	_ sfsm.Store[loginflow.FlowID, loginflow.LoginFlow] = (*FlowStore)(nil)
)

// Create inserts flow and its secret hash.
func (s *FlowStore) Create(ctx context.Context, flow loginflow.LoginFlow, hash loginflow.SecretHash) error {
	id, err := pgUUID(flow.ID)
	if err != nil {
		return err
	}
	err = s.q.CreateLoginFlow(ctx, sqlcgen.CreateLoginFlowParams{
		ID:            id,
		SecretHash:    hash[:],
		State:         string(flow.State),
		Factors:       int32(flow.Factors),
		Version:       int64(flow.Version),
		ReturnUrl:     flow.ReturnURL.String(),
		NeedsSecond:   flow.NeedsSecond,
		PendingFactor: int32(flow.PendingFactor),
		ExpiresAt:     pgTime(flow.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("postgres: create login flow: %w", err)
	}
	return nil
}

// Load returns the flow. An expired row is deleted and reported as ErrFlowNotFound.
func (s *FlowStore) Load(ctx context.Context, id loginflow.FlowID) (loginflow.LoginFlow, error) {
	row, err := s.fetch(ctx, id)
	if err != nil {
		return loginflow.LoginFlow{}, err
	}
	return toFlow(row)
}

// SecretHash returns the stored hash. An expired row is deleted and reported as ErrFlowNotFound.
func (s *FlowStore) SecretHash(ctx context.Context, id loginflow.FlowID) (loginflow.SecretHash, error) {
	row, err := s.fetch(ctx, id)
	if err != nil {
		return loginflow.SecretHash{}, err
	}
	return hashOf(row.SecretHash)
}

// Write updates the row when its version is still prev.Version.
// A final next state deletes the row instead. Zero rows is sfsm.ErrStaleState.
func (s *FlowStore) Write(ctx context.Context, id loginflow.FlowID, prev, next loginflow.LoginFlow) error {
	if next.Version != prev.Version+1 {
		return fmt.Errorf("postgres: login flow version %d does not follow %d", next.Version, prev.Version)
	}
	if prev.ID != id || next.ID != id {
		return fmt.Errorf("postgres: login flow id does not match the write")
	}
	pgID, err := pgUUID(id)
	if err != nil {
		return err
	}
	var n int64
	if next.State.Final() {
		n, err = s.q.DeleteLoginFlowVersion(ctx, sqlcgen.DeleteLoginFlowVersionParams{
			ID:      pgID,
			Version: int64(prev.Version),
		})
	} else {
		n, err = s.q.UpdateLoginFlow(ctx, sqlcgen.UpdateLoginFlowParams{
			State:         string(next.State),
			Factors:       int32(next.Factors),
			NextVersion:   int64(next.Version),
			ReturnUrl:     next.ReturnURL.String(),
			NeedsSecond:   next.NeedsSecond,
			PendingFactor: int32(next.PendingFactor),
			ExpiresAt:     pgTime(next.ExpiresAt),
			ID:            pgID,
			PrevVersion:   int64(prev.Version),
		})
	}
	if err != nil {
		return fmt.Errorf("postgres: write login flow: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("postgres: write login flow: %w", sfsm.ErrStaleState)
	}
	return nil
}

// Cleanup deletes every expired login flow.
func (s *FlowStore) Cleanup(ctx context.Context) error {
	if err := s.q.DeleteExpiredLoginFlows(ctx); err != nil {
		return fmt.Errorf("postgres: cleanup login flows: %w", err)
	}
	return nil
}

func (s *FlowStore) fetch(ctx context.Context, id loginflow.FlowID) (sqlcgen.GetLoginFlowRow, error) {
	pgID, err := pgUUID(id)
	if err != nil {
		return sqlcgen.GetLoginFlowRow{}, err
	}
	row, err := s.q.GetLoginFlow(ctx, pgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlcgen.GetLoginFlowRow{}, loginflow.ErrFlowNotFound
	}
	if err != nil {
		return sqlcgen.GetLoginFlowRow{}, fmt.Errorf("postgres: load login flow: %w", err)
	}
	if row.Expired {
		if err := s.q.DeleteLoginFlow(ctx, pgID); err != nil {
			return sqlcgen.GetLoginFlowRow{}, fmt.Errorf("postgres: delete expired login flow: %w", err)
		}
		return sqlcgen.GetLoginFlowRow{}, loginflow.ErrFlowNotFound
	}
	return row, nil
}

func toFlow(row sqlcgen.GetLoginFlowRow) (loginflow.LoginFlow, error) {
	if !row.ID.Valid {
		return loginflow.LoginFlow{}, errors.New("postgres: login flow id is null")
	}
	if !row.ExpiresAt.Valid {
		return loginflow.LoginFlow{}, errors.New("postgres: login flow expiry is null")
	}
	factors, err := factorsFrom(row.Factors)
	if err != nil {
		return loginflow.LoginFlow{}, err
	}
	pending, err := factorFrom(row.PendingFactor)
	if err != nil {
		return loginflow.LoginFlow{}, err
	}
	return loginflow.LoginFlow{
		ID:            loginflow.FlowIDFromBytes(row.ID.Bytes),
		ReturnURL:     loginflow.ReturnURL(row.ReturnUrl),
		ExpiresAt:     row.ExpiresAt.Time.UTC(),
		State:         loginflow.FlowState(row.State),
		Factors:       factors,
		PendingFactor: pending,
		Version:       loginflow.FlowVersion(row.Version),
		NeedsSecond:   row.NeedsSecond,
	}, nil
}

func hashOf(raw []byte) (loginflow.SecretHash, error) {
	var hash loginflow.SecretHash
	if len(raw) != len(hash) {
		return loginflow.SecretHash{}, fmt.Errorf("postgres: secret hash length %d", len(raw))
	}
	copy(hash[:], raw)
	return hash, nil
}

func factorsFrom(n int32) (loginflow.Factors, error) {
	if n < 0 || n > int32(^loginflow.Factors(0)) {
		return 0, fmt.Errorf("postgres: factors %d", n)
	}
	return loginflow.Factors(n), nil
}

func factorFrom(n int32) (loginflow.Factor, error) {
	if n < 0 || n > int32(^loginflow.Factor(0)) {
		return 0, fmt.Errorf("postgres: pending factor %d", n)
	}
	return loginflow.Factor(n), nil
}

func pgUUID(id loginflow.FlowID) (pgtype.UUID, error) {
	b, err := id.Bytes()
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("postgres: flow id: %w", err)
	}
	return pgtype.UUID{Bytes: b, Valid: true}, nil
}

func pgTime(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC(), Valid: true}
}
