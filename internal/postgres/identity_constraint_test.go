package postgres_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
)

func TestIdentityKindCheckRefusesNullSecrets(t *testing.T) {
	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))
	_, err = pool.Exec(ctx, "INSERT INTO users (id, login, created_at) VALUES (gen_random_uuid(), 'ada', now())")
	require.NoError(t, err)

	insert := "INSERT INTO identities (id, user_id, kind, password_hash, subject, created_at) " +
		"SELECT gen_random_uuid(), id, $1, $2, $3, now() FROM users WHERE login = 'ada'"
	for name, row := range map[string][3]any{
		"password with no hash":    {"password", nil, nil},
		"google with no subject":   {"google", nil, nil},
		"telegram with no subject": {"telegram", nil, nil},
		"unknown kind":             {"other", nil, "x"},
	} {
		t.Run(name, func(t *testing.T) {
			_, insertErr := pool.Exec(ctx, insert, row[0], row[1], row[2])
			require.ErrorContains(t, insertErr, "identities_kind_secret")
		})
	}
	_, err = pool.Exec(ctx, insert, "google", nil, "subject-1")
	require.NoError(t, err, "a valid row MUST pass")
}
