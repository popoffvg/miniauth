// Package postgrestest gives each integration test its own empty database.
package postgrestest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// AdminURLEnv names the variable with the URL of a database whose user may create databases.
const AdminURLEnv = "MINIAUTH_TEST_DATABASE_URL"

// NewDatabase creates an empty database, drops it when the test ends, and returns its URL.
// Without AdminURLEnv the test is skipped, except in CI, where it fails.
func NewDatabase(t *testing.T) string {
	t.Helper()
	admin := os.Getenv(AdminURLEnv)
	if admin == "" {
		if os.Getenv("CI") != "" {
			t.Fatalf("postgrestest: %s is not set in CI", AdminURLEnv)
		}
		t.Skipf("postgrestest: %s is not set; run `task test:integration`", AdminURLEnv)
	}

	name := "miniauth_test_" + randomSuffix(t)
	exec(t, admin, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
	t.Cleanup(func() {
		exec(t, admin, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	})

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("postgrestest: parse %s: %v", AdminURLEnv, err)
	}
	u.Path = "/" + name
	return u.String()
}

func exec(t *testing.T, dsn, sql string) {
	t.Helper()
	ctx := context.WithoutCancel(t.Context())
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("postgrestest: connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("postgrestest: %s: %v", sql, err)
	}
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(fmt.Errorf("postgrestest: random: %w", err))
	}
	return hex.EncodeToString(b)
}
