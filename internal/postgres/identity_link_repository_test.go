package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestIdentityLinkRepository(t *testing.T) {
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
	repo := postgres.NewIdentityLinkRepository(pool)
	links := identitylink.NewService(repo)
	queries := sqlcgen.New(pool)
	subject, err := users.ParseSubject("google-sub")
	if err != nil {
		t.Fatal(err)
	}
	account := users.ExternalAccount{Kind: users.KindGoogle, Subject: subject}

	secret, err := links.Remember(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if _, gotErr := accounts.FindExternalIdentity(ctx, account); !errors.Is(gotErr, users.ErrNotFound) {
		t.Fatalf("FindExternalIdentity before the link = %v, want users.ErrNotFound", gotErr)
	}

	linked, err := links.Complete(ctx, secret, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if linked != account {
		t.Fatalf("linked = %+v, want %+v", linked, account)
	}
	identity, err := accounts.FindExternalIdentity(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != ada.ID || identity.Kind != users.KindGoogle || identity.Subject != subject {
		t.Fatalf("identity = %+v", identity)
	}
	if _, gotErr := links.Complete(ctx, secret, ada.ID); !errors.Is(gotErr, identitylink.ErrNotFound) {
		t.Fatalf("second Complete = %v, want ErrNotFound", gotErr)
	}

	again, err := links.Remember(ctx, account)
	if err != nil {
		t.Fatal(err)
	}
	if _, gotErr := links.Complete(ctx, again, bea.ID); !errors.Is(gotErr, identitylink.ErrAccountTaken) {
		t.Fatalf("Complete for another user = %v, want ErrAccountTaken", gotErr)
	}
	if n, countErr := queries.CountPendingIdentityLinks(ctx); countErr != nil || n != 0 {
		t.Fatalf("pending links after a refused link = %d, %v", n, countErr)
	}

	otherSubject, err := users.ParseSubject("google-sub-expired")
	if err != nil {
		t.Fatal(err)
	}
	expired, err := links.Remember(ctx, users.ExternalAccount{Kind: users.KindGoogle, Subject: otherSubject})
	if err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(identitylink.LinkTTL + time.Minute)
	if _, linkErr := repo.Link(ctx, expired.Hash(), bea.ID, users.NewIdentityID(), later); !errors.Is(linkErr, identitylink.ErrNotFound) {
		t.Fatalf("Link after the TTL = %v, want ErrNotFound", linkErr)
	}
	if err := repo.Cleanup(ctx, later); err != nil {
		t.Fatal(err)
	}
	if n, countErr := queries.CountPendingIdentityLinks(ctx); countErr != nil || n != 0 {
		t.Fatalf("pending links after cleanup = %d, %v", n, countErr)
	}
}
