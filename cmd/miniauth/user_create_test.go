package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/internal/user"
)

func TestUserCreateAndDuplicateLogin(t *testing.T) {
	ctx := t.Context()
	databaseURL := postgrestest.NewDatabase(t)
	const login = "Ada"
	const password = "s3cret-password-for-miniauth-user-create-which-is-longer-than-the-stored-argon2id-string"

	var out bytes.Buffer
	err := runCLI(ctx, []string{"user", "create", "--login", login}, databaseURL, strings.NewReader(password+"\n"), &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "created ada ") {
		t.Fatalf("stdout = %q", out.String())
	}
	if strings.Contains(out.String(), password) {
		t.Fatal("password reached stdout")
	}

	pool, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	row, err := sqlcgen.New(pool).GetIdentityByLogin(ctx, "ada")
	if err != nil {
		t.Fatal(err)
	}
	if row.Kind != string(user.KindPassword) {
		t.Fatalf("kind = %s", row.Kind)
	}
	if !strings.HasPrefix(row.PasswordHash, "$argon2id$") {
		t.Fatal("stored identity is not an argon2id PHC string")
	}
	if strings.Contains(row.PasswordHash, password) {
		t.Fatal("password stored in clear text")
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
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("stored hash does not match the password")
	}
	if !row.UserID.Valid || user.UserIDFromBytes(row.UserID.Bytes).String() == "" {
		t.Fatal("user id is missing")
	}

	err = runCLI(ctx, []string{"user", "create", "--login", "ada"}, databaseURL, strings.NewReader(password+"\n"), &bytes.Buffer{})
	if err == nil {
		t.Fatal("second create succeeded")
	}
	if !strings.Contains(err.Error(), `login "ada" already exists`) {
		t.Fatalf("duplicate error = %q", err.Error())
	}
	if strings.Contains(err.Error(), password) || strings.Contains(err.Error(), "$argon2id$") {
		t.Fatal("duplicate error contains a secret")
	}
	n, err := sqlcgen.New(pool).CountUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("users = %d, want 1", n)
	}
}

func TestUserCreateRejectsEmptyPassword(t *testing.T) {
	err := runCLI(t.Context(), []string{"user", "create", "--login", "ada"}, "postgres://unused", strings.NewReader("\n"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "password is empty") {
		t.Fatalf("error = %v", err)
	}
}

func TestUserCreateRejectsInvalidLogin(t *testing.T) {
	err := runCLI(t.Context(), []string{"user", "create", "--login", "bad login"}, "postgres://unused", strings.NewReader("pw\n"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "is not valid") {
		t.Fatalf("error = %v", err)
	}
}

func TestUserCreateHelp(t *testing.T) {
	var out bytes.Buffer
	err := runCLI(t.Context(), []string{"user", "create", "-h"}, "", strings.NewReader(""), &out)
	if !errors.Is(err, errHelp) {
		t.Fatalf("error = %v", err)
	}
	if !strings.Contains(out.String(), "user create --login") || !strings.Contains(out.String(), "password is read from stdin") {
		t.Fatalf("help = %q", out.String())
	}
}
