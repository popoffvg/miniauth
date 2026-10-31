package postgres_test

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/telegramstep"
)

func TestTelegramProofRepository(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewTelegramProofRepository(pool)
	queries := sqlcgen.New(pool)
	now := time.Now().UTC()
	first := telegramstep.ProofHash(sha256.Sum256([]byte("first")))
	second := telegramstep.ProofHash(sha256.Sum256([]byte("second")))

	if err = repo.Use(ctx, first, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if gotErr := repo.Use(ctx, first, now.Add(time.Hour)); !errors.Is(gotErr, telegramstep.ErrReplay) {
		t.Fatalf("second Use = %v, want ErrReplay", gotErr)
	}
	if err = repo.Use(ctx, second, now); err != nil {
		t.Fatal(err)
	}
	if err = repo.Cleanup(ctx, now); err != nil {
		t.Fatal(err)
	}
	if n, countErr := queries.CountTelegramLoginProofs(ctx); countErr != nil || n != 1 {
		t.Fatalf("proofs after cleanup = %d, %v, want 1", n, countErr)
	}
	if gotErr := repo.Use(ctx, first, now.Add(time.Hour)); !errors.Is(gotErr, telegramstep.ErrReplay) {
		t.Fatalf("Use after cleanup = %v, want ErrReplay for a live row", gotErr)
	}
}
