package postgres_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestTokenRepository(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	accounts := postgres.NewUserRepository(pool)
	ada := createAccount(t, users.NewService(accounts), "ada")
	bea := createAccount(t, users.NewService(accounts), "bea")
	svc := tokens.NewService(postgres.NewTokenRepository(pool))
	name, err := tokens.ParseName("ci")
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := tokens.ParseScopes([]string{"https://app.example.test/mcp", "https://app.example.test/api"})
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)

	secret, issued, err := svc.Issue(ctx, ada.ID, name, scopes, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	hash := secret.Hash()
	row, err := sqlcgen.New(pool).GetAccessTokenByHash(ctx, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(secret.Reveal()))
	if !bytes.Equal(row.SecretHash, sum[:]) {
		t.Fatal("access_tokens did not store the SHA-256")
	}
	if row.DisplayPrefix != secret.Reveal()[:8] {
		t.Fatalf("display prefix = %q", row.DisplayPrefix)
	}

	// A new service is a process restart.
	restarted := tokens.NewService(postgres.NewTokenRepository(pool))
	got, err := restarted.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != issued.ID || got.UserID != ada.ID || !got.ExpiresAt.Equal(expiresAt) || got.LastUsedAt.IsZero() {
		t.Fatalf("token = %+v", got)
	}
	if len(got.Scopes) != 2 || got.Scopes[0].String() != "https://app.example.test/mcp" {
		t.Fatalf("scopes = %v", got.Scopes.Strings())
	}
	again, err := restarted.Authenticate(ctx, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !again.LastUsedAt.Equal(got.LastUsedAt) {
		t.Fatal("last_used_at moved within one minute")
	}

	list, err := svc.List(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != issued.ID {
		t.Fatalf("list = %d tokens", len(list))
	}
	if err = svc.Revoke(ctx, bea.ID, issued.ID); !errors.Is(err, tokens.ErrNotFound) {
		t.Fatalf("revoke by another user: %v", err)
	}
	if err = svc.Revoke(ctx, ada.ID, issued.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Authenticate(ctx, secret); !errors.Is(err, tokens.ErrInvalid) {
		t.Fatalf("revoked token: %v", err)
	}

	if _, err = svc.Import(ctx, bea.ID, name, nil, secret); !errors.Is(err, tokens.ErrDuplicate) {
		t.Fatalf("import of a stored token: %v", err)
	}
	if _, _, err = svc.Issue(ctx, users.NewID(), name, nil, time.Time{}); !errors.Is(err, tokens.ErrUnknownUser) {
		t.Fatalf("issue for an unknown user: %v", err)
	}
	other, err := tokens.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := svc.Import(ctx, bea.ID, name, nil, other)
	if err != nil {
		t.Fatal(err)
	}
	got, err = svc.Authenticate(ctx, other)
	if err != nil || got.ID != imported.ID || !got.ExpiresAt.IsZero() || len(got.Scopes) != 0 {
		t.Fatalf("imported token = %+v, %v", got, err)
	}
}

func TestDisableUser(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewUserRepository(pool)
	ada := createAccount(t, users.NewService(repo), "ada")
	if ada.Disabled() {
		t.Fatal("new user is disabled")
	}
	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err = repo.Disable(ctx, ada.ID, first); err != nil {
		t.Fatal(err)
	}
	if err = repo.Disable(ctx, ada.ID, first.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.Find(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.Disabled() || !stored.DisabledAt.Equal(first) {
		t.Fatalf("disabled_at = %v", stored.DisabledAt)
	}
	if _, err = repo.FindPasswordIdentity(ctx, ada.Login); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("password identity of a disabled user: %v", err)
	}
	if err = repo.Disable(ctx, users.NewID(), first); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("disable unknown user: %v", err)
	}
}
