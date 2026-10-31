// Package postgres is the PostgreSQL adapter: the connection pool, the migrations, and the sqlc queries.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/popoffvg/miniauth/internal/postgres/sqlcgen"
	"github.com/popoffvg/miniauth/migrations"
)

// Open connects to the database at dsn and checks the connection.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	cfg.ConnConfig.Tracer = queryTracer{}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return pool, nil
}

// Migrate applies every embedded migration that the database does not have yet, a lower number after a higher one too.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()

	// Branches merge out of number order, so a database can run a higher number before a lower one arrives.
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithAllowOutofOrder(true))
	if err != nil {
		return fmt.Errorf("postgres: migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("postgres: migrate up: %w", err)
	}
	return nil
}

// Probe opens one new connection and runs Ping.
// A pooled connection can stay open after PostgreSQL stops, so the probe does not use one.
// The error MUST NOT be logged. The driver can put the connection string in it.
func Probe(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("postgres: probe: no pool")
	}
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig.Copy())
	if err != nil {
		return fmt.Errorf("postgres: probe: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	ok, err := sqlcgen.New(conn).Ping(ctx)
	if err != nil {
		return fmt.Errorf("postgres: probe: %w", err)
	}
	if ok != 1 {
		return errors.New("postgres: probe: unexpected result")
	}
	return nil
}
