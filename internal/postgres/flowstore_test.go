package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
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
	ada := createAccount(t, users.NewService(postgres.NewUserRepository(pool)), "ada")

	t.Run("stale write and final delete", func(t *testing.T) {
		id, secret, err := flows.Start(ctx, returnURL)
		if err != nil {
			t.Fatal(err)
		}
		assertHashIsNotSecret(ctx, t, store, id, secret)

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
			UserID:      ada.ID,
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
		if stored.State != loginflow.StateAwaitingSecond || stored.Version != 1 || !stored.NeedsSecond || !stored.Factors.Has(loginflow.FactorPassword) || stored.UserID != ada.ID {
			t.Fatalf("stored flow = %+v", stored)
		}

		third, err := flows.Open(ctx, id, secret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = third.Close() })
		if err = third.Apply(ctx, loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorTOTP, UserID: ada.ID}); err != nil {
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
		expiredHash, err := expiredSecret.Hash()
		if err != nil {
			t.Fatal(err)
		}
		err = store.Create(ctx, loginflow.LoginFlow{
			ID:        expiredID,
			ReturnURL: returnURL,
			ExpiresAt: time.Now().Add(-time.Minute).UTC(),
			State:     loginflow.StateAwaiting,
			Kind:      loginflow.KindLogin,
		}, expiredHash)
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

	t.Run("a flow that expires after load does not complete", func(t *testing.T) {
		id, err := loginflow.NewFlowID()
		if err != nil {
			t.Fatal(err)
		}
		secret, err := loginflow.NewFlowSecret()
		if err != nil {
			t.Fatal(err)
		}
		hash, err := secret.Hash()
		if err != nil {
			t.Fatal(err)
		}
		flow := loginflow.LoginFlow{ID: id, ReturnURL: returnURL, ExpiresAt: time.Now().Add(time.Second).UTC(), State: loginflow.StateAwaiting, Kind: loginflow.KindLogin}
		if err = store.Create(ctx, flow, hash); err != nil {
			t.Fatal(err)
		}
		prev, err := store.Load(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		next, err := prev.Next(loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorPassword, UserID: ada.ID})
		if err != nil {
			t.Fatal(err)
		}
		if err = store.Write(ctx, id, prev, next); !errors.Is(err, loginflow.ErrFlowNotFound) {
			t.Fatalf("Write() of a complete flow after expiry = %v, want ErrFlowNotFound", err)
		}
	})
}

func assertHashIsNotSecret(ctx context.Context, t *testing.T, store *postgres.FlowStore, id loginflow.FlowID, secret loginflow.FlowSecret) {
	t.Helper()
	hash, err := store.SecretHash(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	raw := secret.Bytes()
	if bytes.Equal(hash.Digest[:], raw[:]) {
		t.Fatal("database holds the flow secret")
	}
	unsalted := sha256.Sum256(raw[:])
	if bytes.Equal(hash.Digest[:], unsalted[:]) {
		t.Fatal("database holds the unsalted SHA-256 of the flow secret")
	}
	if hash.Salt == (loginflow.SecretSalt{}) {
		t.Fatal("database holds an empty salt")
	}
	if !secret.Matches(hash) {
		t.Fatal("stored hash does not match the secret")
	}
}
