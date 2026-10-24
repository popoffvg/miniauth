package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/user"
)

func TestCreateUserStoresAnArgon2Identity(t *testing.T) {
	t.Logf("gofakeit seed %d", fakeSeed+1)
	fake := gofakeit.New(fakeSeed + 1)
	login := fake.Regex(`[a-z][a-z0-9]{7}`)
	password := fake.Password(true, true, true, true, false, 24)
	const token = "bootstrap-token-for-tests"

	ctx := t.Context()
	pool, err := postgres.Open(ctx, postgrestest.NewDatabase(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, postgres.Migrate(ctx, pool))

	router := mustRouter(t, postgres.NewUserRepository(pool), token)
	body := `{"login":"` + login + `","password":"` + password + `"}`

	missing := post(t, router, "", body, "application/json")
	require.Equal(t, http.StatusUnauthorized, missing.Code)
	assert.NotContains(t, missing.Body.String(), password)

	wrong := post(t, router, "wrong-token", body, "application/json")
	require.Equal(t, http.StatusUnauthorized, wrong.Code)
	assert.NotContains(t, wrong.Body.String(), password)

	createdRec := post(t, router, token, body, "application/json")
	require.Equal(t, http.StatusCreated, createdRec.Code)
	var created createdUser
	require.NoError(t, json.Unmarshal(createdRec.Body.Bytes(), &created))
	assert.Equal(t, login, created.Login.String())
	assert.NotContains(t, createdRec.Body.String(), password)

	row, err := sqlcgen.New(pool).GetIdentityByLogin(ctx, login)
	require.NoError(t, err)
	assert.Equal(t, string(user.KindPassword), row.Kind)
	assert.True(t, strings.HasPrefix(row.PasswordHash, "$argon2id$"))
	assert.NotContains(t, row.PasswordHash, password)
	hash, err := user.ParsePasswordHash(row.PasswordHash)
	require.NoError(t, err)
	pw, err := user.NewPassword(password)
	require.NoError(t, err)
	matches, err := hash.Matches(pw)
	require.NoError(t, err)
	assert.True(t, matches)
	assert.True(t, row.UserID.Valid)
	assert.Equal(t, created.ID.String(), user.UserIDFromBytes(row.UserID.Bytes).String())

	again := post(t, router, token, body, "application/json")
	require.Equal(t, http.StatusConflict, again.Code)
	assert.NotContains(t, again.Body.String(), password)
	assert.NotContains(t, again.Body.String(), row.PasswordHash)
	n, err := sqlcgen.New(pool).CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}
