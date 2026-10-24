package postgres_test

import (
	"testing"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

func TestMigrateAppliesEveryMigrationOnce(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	for range 2 {
		if err = postgres.Migrate(ctx, pool); err != nil {
			t.Fatal(err)
		}
	}

	var version int64
	if err = pool.QueryRow(ctx, "SELECT max(version_id) FROM goose_db_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("goose version: got %d, want 2", version)
	}

	ok, err := sqlcgen.New(pool).Ping(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok != 1 {
		t.Fatalf("Ping: got %d, want 1", ok)
	}
}
