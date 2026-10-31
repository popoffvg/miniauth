package postgres_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
)

func TestMigrateAppliesEveryMigrationOnce(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	for range 2 {
		require.NoError(t, postgres.Migrate(ctx, pool))
	}

	var version int64
	require.NoError(t, pool.QueryRow(ctx, "SELECT max(version_id) FROM goose_db_version").Scan(&version))
	assert.Equal(t, int64(7), version)

	ok, err := sqlcgen.New(pool).Ping(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), ok)
	require.NoError(t, postgres.Probe(ctx, pool))
}

func TestProbeErrorHidesTheConnectionString(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	err = postgres.Probe(cancelled, pool)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "postgres://")
	assert.NotContains(t, err.Error(), "password=")
}
