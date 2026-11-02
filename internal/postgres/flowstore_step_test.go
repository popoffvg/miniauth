package postgres_test

import (
	"errors"
	"testing"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
)

func TestFlowStoreStepState(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	store := postgres.NewFlowStore(pool)
	returnURL, err := loginflow.NewReturnURL("https://example.test/app")
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := loginflow.NewLoginFlows(store).Start(ctx, returnURL)
	if err != nil {
		t.Fatal(err)
	}

	if state, loadErr := store.LoadStep(ctx, id); loadErr != nil || state != "" {
		t.Fatalf("LoadStep() of a new flow = %q, %v, want the empty state", state, loadErr)
	}
	if err = store.BeginStep(ctx, id, "started"); err != nil {
		t.Fatal(err)
	}
	if err = store.MoveStep(ctx, id, "started", "passed"); err != nil {
		t.Fatal(err)
	}
	if err = store.MoveStep(ctx, id, "started", "failed"); !errors.Is(err, loginflow.ErrStepMoved) {
		t.Fatalf("second MoveStep() error = %v, want %v", err, loginflow.ErrStepMoved)
	}
	if state, loadErr := store.LoadStep(ctx, id); loadErr != nil || state != "passed" {
		t.Fatalf("LoadStep() = %q, %v, want passed", state, loadErr)
	}

	missing, err := loginflow.NewFlowID()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BeginStep(ctx, missing, "started"); !errors.Is(err, loginflow.ErrFlowNotFound) {
		t.Fatalf("BeginStep() of a missing flow error = %v, want %v", err, loginflow.ErrFlowNotFound)
	}
	if _, err = store.LoadStep(ctx, missing); !errors.Is(err, loginflow.ErrFlowNotFound) {
		t.Fatalf("LoadStep() of a missing flow error = %v, want %v", err, loginflow.ErrFlowNotFound)
	}
}
