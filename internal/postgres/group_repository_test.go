package postgres_test

import (
	"errors"
	"testing"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestGroupMembershipRoundTrip(t *testing.T) {
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
	repo := postgres.NewGroupRepository(pool)
	editors, err := groups.ParseName("Editors")
	if err != nil {
		t.Fatal(err)
	}
	readers, err := groups.ParseName("readers")
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.Add(ctx, ada.ID, editors); err != nil {
		t.Fatal(err)
	}
	if err = repo.Add(ctx, ada.ID, readers); err != nil {
		t.Fatal(err)
	}
	if err = repo.Add(ctx, ada.ID, editors); !errors.Is(err, groups.ErrDuplicate) {
		t.Fatalf("duplicate = %v", err)
	}
	if err = repo.Add(ctx, users.NewID(), editors); !errors.Is(err, groups.ErrUnknownUser) {
		t.Fatalf("unknown user = %v", err)
	}

	got, err := repo.List(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "editors" || got[1].String() != "readers" {
		t.Fatalf("groups = %v", got)
	}
	loaded, err := accounts.Find(ctx, ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Login != ada.Login {
		t.Fatalf("login = %s", loaded.Login)
	}
}
