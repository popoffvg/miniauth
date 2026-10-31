package postgres_test

import (
	"context"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/migrations"
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
	assert.Equal(t, highestMigration(t), version)

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

// highestMigration reads the version from the file names, so a new migration needs no test change.
func highestMigration(t *testing.T) int64 {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	var highest int64
	for _, name := range names {
		number, _, ok := strings.Cut(name, "_")
		require.True(t, ok, name)
		version, err := strconv.ParseInt(number, 10, 64)
		require.NoError(t, err, name)
		highest = max(highest, version)
	}
	require.NotZero(t, highest)
	return highest
}
