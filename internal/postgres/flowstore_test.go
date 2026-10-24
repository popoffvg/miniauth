package postgres_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

func TestLoginFlowEngine(t *testing.T) {
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
	flows := loginflow.NewLoginFlows(store)
	returnURL, err := loginflow.NewReturnURL("https://example.test/app")
	if err != nil {
		t.Fatal(err)
	}
	queries := sqlcgen.New(pool)

	t.Run("stale write and final delete", func(t *testing.T) {
		id, secret, err := flows.Start(ctx, returnURL)
		if err != nil {
			t.Fatal(err)
		}
		assertHashIsNotSecret(t, store, id, secret)

		first, err := flows.Open(ctx, id, secret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = first.Close() })
		second, err := flows.Open(ctx, id, secret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = second.Close() })

		passed := loginflow.Event{
			Kind:        loginflow.EventStepPassed,
			Factor:      loginflow.FactorPassword,
			NeedsSecond: true,
		}
		if err = first.Apply(ctx, passed); err != nil {
			t.Fatal(err)
		}
		err = second.Apply(ctx, passed)
		if !errors.Is(err, sfsm.ErrStaleState) {
			t.Fatalf("second Apply() error = %v, want ErrStaleState", err)
		}
		if got := second.Get(); got.Version != 0 || got.State != loginflow.StateAwaiting {
			t.Fatalf("stale machine state = %+v", got)
		}

		stored, err := store.Load(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if stored.State != loginflow.StateAwaitingSecond || stored.Version != 1 || !stored.NeedsSecond || !stored.Factors.Has(loginflow.FactorPassword) {
			t.Fatalf("stored flow = %+v", stored)
		}

		third, err := flows.Open(ctx, id, secret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = third.Close() })
		if err = third.Apply(ctx, loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorTOTP}); err != nil {
			t.Fatal(err)
		}
		if third.Get().State != loginflow.StateComplete {
			t.Fatalf("state = %s, want complete", third.Get().State)
		}
		_, err = store.Load(ctx, id)
		if !errors.Is(err, loginflow.ErrFlowNotFound) {
			t.Fatalf("load after complete = %v, want ErrFlowNotFound", err)
		}
	})

	t.Run("expired flow is cleaned up", func(t *testing.T) {
		liveID, liveSecret, err := flows.Start(ctx, returnURL)
		if err != nil {
			t.Fatal(err)
		}
		expiredID, err := loginflow.NewFlowID()
		if err != nil {
			t.Fatal(err)
		}
		expiredSecret, err := loginflow.NewFlowSecret()
		if err != nil {
			t.Fatal(err)
		}
		err = store.Create(ctx, loginflow.LoginFlow{
			ID:        expiredID,
			ReturnURL: returnURL,
			ExpiresAt: time.Now().Add(-time.Minute).UTC(),
			State:     loginflow.StateAwaiting,
		}, expiredSecret.Hash())
		if err != nil {
			t.Fatal(err)
		}

		before, err := queries.CountLoginFlows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if before < 2 {
			t.Fatalf("rows before open = %d, want at least 2", before)
		}

		_, err = flows.Open(ctx, expiredID, expiredSecret)
		if !errors.Is(err, loginflow.ErrFlowNotFound) {
			t.Fatalf("open expired = %v, want ErrFlowNotFound", err)
		}
		after, err := queries.CountLoginFlows(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if after != before-1 {
			t.Fatalf("rows after expired open = %d, want %d", after, before-1)
		}

		wrong, err := loginflow.NewFlowSecret()
		if err != nil {
			t.Fatal(err)
		}
		_, err = flows.Open(ctx, liveID, wrong)
		if !errors.Is(err, loginflow.ErrFlowNotFound) {
			t.Fatalf("open wrong secret = %v, want ErrFlowNotFound", err)
		}
		live, err := flows.Open(ctx, liveID, liveSecret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = live.Close() })
		if err = live.Apply(ctx, loginflow.Event{Kind: loginflow.EventCancel}); err != nil {
			t.Fatal(err)
		}
		if live.Get().State != loginflow.StateCancelled {
			t.Fatalf("state = %s, want cancelled", live.Get().State)
		}
		_, err = store.Load(ctx, liveID)
		if !errors.Is(err, loginflow.ErrFlowNotFound) {
			t.Fatalf("load after cancel = %v, want ErrFlowNotFound", err)
		}
	})
}

func assertHashIsNotSecret(t *testing.T, store *postgres.FlowStore, id loginflow.FlowID, secret loginflow.FlowSecret) {
	t.Helper()
	hash, err := store.SecretHash(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	raw := secret.Bytes()
	if bytes.Equal(hash[:], raw[:]) {
		t.Fatal("database holds the flow secret")
	}
	if !secret.Matches(hash) {
		t.Fatal("stored hash does not match the secret")
	}
}
