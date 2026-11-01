package postgres_test

import (
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/migrations"
)

// The groups migration runs on rows that the earlier schema allowed.
func TestGroupsMigrationRenamesAdminAndSeedsGroups(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	db := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { _ = db.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	require.NoError(t, err)
	const groupsMigration = 20
	_, err = provider.UpTo(ctx, groupsMigration-1)
	require.NoError(t, err)

	for _, statement := range []string{
		`INSERT INTO users (id, login, created_at) VALUES
			('00000000-0000-0000-0000-00000000000a', 'ada', now()),
			('00000000-0000-0000-0000-00000000000b', 'bob', now())`,
		`INSERT INTO group_memberships (user_id, name) VALUES
			('00000000-0000-0000-0000-00000000000a', 'admin'),
			('00000000-0000-0000-0000-00000000000a', 'admins'),
			('00000000-0000-0000-0000-00000000000b', 'editors')`,
		`INSERT INTO resources (name, host, path_prefix) VALUES ('app', 'app.example.test', '/'), ('wiki', 'wiki.example.test', '/')`,
		`INSERT INTO access_grants (id, resource_name, group_name, created_at) VALUES
			('00000000-0000-0000-0000-0000000000a1', 'app', 'admin', now()),
			('00000000-0000-0000-0000-0000000000a2', 'wiki', 'readers', now())`,
		`INSERT INTO invites (token_hash, resource_name, created_at, expires_at)
			VALUES (decode(repeat('ab', 32), 'hex'), 'app', now(), now() + interval '1 day')`,
		`INSERT INTO invites (token_hash, resource_name, created_at, expires_at, used_at, user_id)
			VALUES (decode(repeat('cd', 32), 'hex'), 'app', now(), now() + interval '1 day', now(), '00000000-0000-0000-0000-00000000000b')`,
	} {
		_, err = pool.Exec(ctx, statement)
		require.NoError(t, err, statement)
	}

	_, err = provider.UpTo(ctx, groupsMigration)
	require.NoError(t, err)

	column := func(query string) []string {
		t.Helper()
		rows, queryErr := pool.Query(ctx, query)
		require.NoError(t, queryErr)
		var found []string
		for rows.Next() {
			var value string
			require.NoError(t, rows.Scan(&value))
			found = append(found, value)
		}
		require.NoError(t, rows.Err())
		return found
	}
	assert.Equal(t, []string{"admins", "editors", "readers", "users"}, column(`SELECT name FROM groups ORDER BY name`))
	assert.Equal(t, []string{"admins", "users"}, column(`SELECT name FROM groups WHERE built_in ORDER BY name`))
	assert.Equal(t, []string{"ada:admins", "ada:users", "bob:editors", "bob:users"}, column(
		`SELECT users.login || ':' || gm.name FROM group_memberships gm JOIN users ON users.id = gm.user_id ORDER BY 1`))
	assert.Equal(t, []string{"app:admins", "wiki:readers"}, column(`SELECT resource_name || ':' || group_name FROM access_grants ORDER BY 1`))
	assert.Equal(t, []string{"users"}, column(`SELECT group_name FROM invites`), "the open invite is deleted, the used one names users")

	_, err = pool.Exec(ctx, `INSERT INTO group_memberships (user_id, name) VALUES ('00000000-0000-0000-0000-00000000000b', 'ghosts')`)
	require.Error(t, err, "a membership MUST name a stored group")
	_, err = pool.Exec(ctx, `DELETE FROM groups WHERE name = 'editors'`)
	require.NoError(t, err)
	assert.Equal(t, []string{"bob:users"}, column(
		`SELECT users.login || ':' || gm.name FROM group_memberships gm JOIN users ON users.id = gm.user_id WHERE users.login = 'bob' ORDER BY 1`),
		"a group delete MUST delete its memberships")
}
