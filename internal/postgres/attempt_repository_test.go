package postgres_test

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/users"
)

func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestAttemptRepositoryCountsFailures(t *testing.T) {
	ctx := t.Context()
	repo := postgres.NewAttemptRepository(migratedPool(t))
	start := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	ada := mustLogin(t, "ada")
	bea := mustLogin(t, "bea")
	home := mustClientIP(t, "2001:db8:0:1::1")
	sameNet := mustClientIP(t, "2001:db8:0:1::99")
	other := mustClientIP(t, "192.0.2.1")
	record := func(login users.Login, ip passwordstep.ClientIP, ok bool, at time.Time) {
		t.Helper()
		err := repo.Record(ctx, passwordstep.Attempt{Kind: passwordstep.KindPassword, Login: login, IP: ip, Succeeded: ok, AttemptedAt: at})
		if err != nil {
			t.Fatal(err)
		}
	}
	record(ada, home, false, start)
	record(ada, other, false, start.Add(time.Minute))
	record(ada, home, true, start.Add(2*time.Minute))
	record(ada, home, false, start.Add(3*time.Minute))
	record(bea, sameNet, false, start.Add(4*time.Minute))

	got, err := repo.CountFailures(ctx, passwordstep.KindPassword, mustLogin(t, " ADA "), home, start)
	if err != nil {
		t.Fatal(err)
	}
	want := passwordstep.RecentFailures{
		// The success at +2m resets the login count.
		Login: passwordstep.FailureCount{Failures: 1, LastFailure: start.Add(3 * time.Minute)},
		// The success does not reset the IP count. bea counts: one /64 is one client.
		IP: passwordstep.FailureCount{Failures: 3, LastFailure: start.Add(4 * time.Minute)},
	}
	if got != want {
		t.Fatalf("CountFailures() = %+v, want %+v", got, want)
	}

	got, err = repo.CountFailures(ctx, passwordstep.KindPassword, bea, other, start.Add(90*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	want = passwordstep.RecentFailures{
		Login: passwordstep.FailureCount{Failures: 1, LastFailure: start.Add(4 * time.Minute)},
	}
	if got != want {
		t.Fatalf("CountFailures() since +90s = %+v, want %+v", got, want)
	}

	if err = repo.Cleanup(ctx, start.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, err = repo.CountFailures(ctx, passwordstep.KindPassword, ada, other, start)
	if err != nil {
		t.Fatal(err)
	}
	want = passwordstep.RecentFailures{
		Login: passwordstep.FailureCount{Failures: 1, LastFailure: start.Add(3 * time.Minute)},
	}
	if got != want {
		t.Fatalf("CountFailures() after cleanup = %+v, want %+v", got, want)
	}
}

func TestAttemptRepositoryPasswordSuccessKeepsTheSecondFactorCount(t *testing.T) {
	ctx := t.Context()
	repo := postgres.NewAttemptRepository(migratedPool(t))
	start := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	ada := mustLogin(t, "ada")
	ip := mustClientIP(t, "192.0.2.7")
	record := func(kind passwordstep.AttemptKind, ok bool, at time.Time) {
		t.Helper()
		err := repo.Record(ctx, passwordstep.Attempt{Kind: kind, Login: ada, IP: ip, Succeeded: ok, AttemptedAt: at})
		if err != nil {
			t.Fatal(err)
		}
	}
	record(passwordstep.KindSecondFactor, false, start)
	record(passwordstep.KindPassword, true, start.Add(time.Minute))
	record(passwordstep.KindSecondFactor, false, start.Add(2*time.Minute))

	got, err := repo.CountFailures(ctx, passwordstep.KindSecondFactor, ada, ip, start)
	if err != nil {
		t.Fatal(err)
	}
	want := passwordstep.RecentFailures{
		Login: passwordstep.FailureCount{Failures: 2, LastFailure: start.Add(2 * time.Minute)},
		IP:    passwordstep.FailureCount{Failures: 2, LastFailure: start.Add(2 * time.Minute)},
	}
	if got != want {
		t.Fatalf("CountFailures(second factor) = %+v, want %+v", got, want)
	}
	got, err = repo.CountFailures(ctx, passwordstep.KindPassword, ada, ip, start)
	if err != nil {
		t.Fatal(err)
	}
	if got.Login.Failures != 0 || got.IP.Failures != 2 {
		t.Fatalf("CountFailures(password) = %+v, want no login failures and 2 IP failures", got)
	}
}

func TestPasswordStepOnLoginFlow(t *testing.T) {
	ctx := t.Context()
	pool := migratedPool(t)
	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	right, err := users.NewPassword("test-password-1")
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := users.NewPassword("test-password-2")
	if err != nil {
		t.Fatal(err)
	}
	store := postgres.NewFlowStore(pool)
	flows := loginflow.NewLoginFlows(store)
	step, err := passwordstep.NewService(postgres.NewUserRepository(pool), postgres.NewAttemptRepository(pool))
	if err != nil {
		t.Fatal(err)
	}
	returnURL, err := loginflow.NewReturnURL("https://example.test/app")
	if err != nil {
		t.Fatal(err)
	}
	open := func(t *testing.T) (loginflow.FlowID, passwordstep.Flow) {
		t.Helper()
		id, secret, err := flows.Start(ctx, returnURL)
		if err != nil {
			t.Fatal(err)
		}
		machine, err := flows.Open(ctx, id, secret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = machine.Close() })
		return id, machine
	}

	t.Run("right password completes the flow", func(t *testing.T) {
		id, flow := open(t)
		userID, err := step.Verify(ctx, flow, mustLogin(t, "Ada"), right, mustClientIP(t, "192.0.2.10"))
		if err != nil {
			t.Fatal(err)
		}
		if userID != ada.ID {
			t.Fatalf("Verify() = %s, want %s", userID, ada.ID)
		}
		if _, err = store.Load(ctx, id); !errors.Is(err, loginflow.ErrFlowNotFound) {
			t.Fatalf("load after complete = %v, want ErrFlowNotFound", err)
		}
	})

	t.Run("wrong password and unknown login keep the flow", func(t *testing.T) {
		id, flow := open(t)
		ip := mustClientIP(t, "192.0.2.11")
		if _, err := step.Verify(ctx, flow, mustLogin(t, "ada"), wrong, ip); !errors.Is(err, passwordstep.ErrWrongCredentials) {
			t.Fatalf("wrong password error = %v", err)
		}
		if _, err := step.Verify(ctx, flow, mustLogin(t, "nobody"), right, ip); !errors.Is(err, passwordstep.ErrWrongCredentials) {
			t.Fatalf("unknown login error = %v", err)
		}
		stored, err := store.Load(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if stored.State != loginflow.StateAwaiting || stored.Factors != 0 {
			t.Fatalf("stored flow = %+v", stored)
		}
	})

	t.Run("five failures from one IP start the backoff", func(t *testing.T) {
		_, flow := open(t)
		ip := mustClientIP(t, "198.51.100.7")
		for i := range passwordstep.FreeFailures {
			guess := mustLogin(t, fmt.Sprintf("guess%d", i))
			if _, err := step.Verify(ctx, flow, guess, wrong, ip); !errors.Is(err, passwordstep.ErrWrongCredentials) {
				t.Fatalf("failure error = %v", err)
			}
		}
		_, err := step.Verify(ctx, flow, mustLogin(t, "ada"), right, ip)
		if !errors.Is(err, passwordstep.ErrTooSoon) {
			t.Fatalf("sixth try error = %v, want ErrTooSoon", err)
		}
		_, err = step.Verify(ctx, flow, mustLogin(t, "ada"), right, mustClientIP(t, "203.0.113.1"))
		if err != nil {
			t.Fatalf("ada from another IP error = %v", err)
		}
	})
}

func mustLogin(t *testing.T, raw string) users.Login {
	t.Helper()
	login, err := users.ParseLogin(raw)
	if err != nil {
		t.Fatal(err)
	}
	return login
}

func mustClientIP(t *testing.T, raw string) passwordstep.ClientIP {
	t.Helper()
	ip, err := passwordstep.NewClientIP(netip.MustParseAddr(raw))
	if err != nil {
		t.Fatal(err)
	}
	return ip
}
