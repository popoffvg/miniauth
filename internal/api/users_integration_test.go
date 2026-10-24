package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/user"
)

func TestCreateUserStoresAnArgon2Identity(t *testing.T) {
	ctx := t.Context()
	databaseURL := postgrestest.NewDatabase(t)
	pool, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = postgres.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}

	h := newHarness(t, postgres.NewUserRepository(pool))
	const password = "s3cret-password-for-miniauth-user-create-which-is-longer-than-the-stored-argon2id-string"
	body := `{"login":"Ada","password":"` + password + `"}`

	rec := h.post(t, "", body, "application/json")
	assertProblem(t, rec, http.StatusUnauthorized)
	assertNoSecret(t, rec.Body.String(), password, h.token)

	rec = h.post(t, "wrong-token", body, "application/json")
	assertProblem(t, rec, http.StatusUnauthorized)
	assertNoSecret(t, rec.Body.String(), password, h.token, "wrong-token")

	rec = h.post(t, h.token, body, "application/json")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d; body contains secret: %v", rec.Code, strings.Contains(rec.Body.String(), password))
	}
	var created createdUser
	if err = json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Login != "ada" {
		t.Fatalf("login = %s", created.Login)
	}
	if _, err = created.ID.Bytes(); err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, rec.Body.String(), password)

	row, err := sqlcgen.New(pool).GetIdentityByLogin(ctx, "ada")
	if err != nil {
		t.Fatal(err)
	}
	if row.Kind != string(user.KindPassword) {
		t.Fatalf("kind = %s", row.Kind)
	}
	if !strings.HasPrefix(row.PasswordHash, "$argon2id$") || strings.Contains(row.PasswordHash, password) {
		t.Fatal("stored identity is not an argon2id PHC string")
	}
	hash, err := user.ParsePasswordHash(row.PasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := user.NewPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := hash.Matches(pw)
	if err != nil || !ok {
		t.Fatalf("Matches() = %v, %v", ok, err)
	}
	if !row.UserID.Valid || user.UserIDFromBytes(row.UserID.Bytes).String() != created.ID.String() {
		t.Fatal("stored user id does not match the response")
	}

	rec = h.post(t, h.token, body, "application/json")
	assertProblem(t, rec, http.StatusConflict)
	assertNoSecret(t, rec.Body.String(), password, row.PasswordHash, h.token)
	n, err := sqlcgen.New(pool).CountUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}
