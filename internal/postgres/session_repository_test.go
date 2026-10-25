package postgres_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestSessionSurvivesRestart(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	accounts := users.NewService(postgres.NewUserRepository(pool))
	ada := createAccount(t, accounts, "ada")
	bea := createAccount(t, accounts, "bea")
	repo := postgres.NewSessionRepository(pool)
	svc := sessions.NewService(repo)
	factors := loginflow.Factors(loginflow.FactorPassword | loginflow.FactorTOTP)
	id, started, err := svc.Start(ctx, ada.ID, factors)
	if err != nil {
		t.Fatal(err)
	}

	hash := id.Hash()
	row, err := sqlcgen.New(pool).GetSession(ctx, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := id.Bytes()
	if bytes.Equal(row.SecretHash, raw[:]) {
		t.Fatal("sessions table stored the cookie")
	}
	sum := sha256.Sum256(raw[:])
	if !bytes.Equal(row.SecretHash, sum[:]) {
		t.Fatal("sessions table did not store the SHA-256")
	}
	if len(row.SecretHash) != sha256.Size {
		t.Fatalf("hash length = %d", len(row.SecretHash))
	}

	// A new service is a process restart. It has no session in memory.
	restarted := sessions.NewService(postgres.NewSessionRepository(pool))
	opened, extended, err := restarted.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if extended {
		t.Fatal("the first read extended the session")
	}
	if opened.UserID != ada.ID || opened.Factors != factors {
		t.Fatalf("opened = %+v", opened)
	}
	if !opened.AuthAt.Equal(started.AuthAt) || !opened.ExpiresAt.Equal(started.ExpiresAt) {
		t.Fatalf("times auth %s/%s expires %s/%s", opened.AuthAt, started.AuthAt, opened.ExpiresAt, started.ExpiresAt)
	}

	wrote, err := repo.Extend(ctx, id.Hash(), time.Now().Add(sessions.Lifetime), started.ExpiresAt.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Fatal("extend wrote inside the hour")
	}
	again, _, err := restarted.Open(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !again.ExpiresAt.Equal(started.ExpiresAt) {
		t.Fatalf("expires_at moved to %s", again.ExpiresAt)
	}

	second, _, err := svc.Start(ctx, ada.ID, loginflow.Factors(loginflow.FactorPassword))
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := svc.Start(ctx, bea.ID, loginflow.Factors(loginflow.FactorGoogle))
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Logout(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err = restarted.Open(ctx, id); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("open after logout = %v", err)
	}
	if _, _, err = restarted.Open(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err = restarted.LogoutEverywhere(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, _, err = restarted.Open(ctx, second); !errors.Is(err, sessions.ErrNotFound) {
		t.Fatalf("second after logout everywhere = %v", err)
	}
	if _, _, err = restarted.Open(ctx, other); err != nil {
		t.Fatal(err)
	}
	n, err := sqlcgen.New(pool).CountSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("sessions = %d, want 1", n)
	}

	_, _, err = sessions.NewService(postgres.NewSessionRepository(pool)).Start(ctx, users.NewID(), loginflow.Factors(loginflow.FactorPassword))
	if !errors.Is(err, sessions.ErrUnknownUser) {
		t.Fatalf("unknown user = %v", err)
	}
}

func createAccount(t *testing.T, accounts *users.Service, login string) users.User {
	t.Helper()
	name, err := users.ParseLogin(login)
	if err != nil {
		t.Fatal(err)
	}
	password, err := users.NewPassword("test-password-1")
	if err != nil {
		t.Fatal(err)
	}
	account, err := accounts.Create(t.Context(), name, password)
	if err != nil {
		t.Fatal(err)
	}
	return account
}
