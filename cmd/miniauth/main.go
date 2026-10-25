// Command miniauth serves login, sessions, personal access tokens, and the forward-auth check.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/telemetry"
	"github.com/popoffvg/miniauth/internal/users"
)

const shutdownTimeout = 10 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := rejectArgs(os.Args[1:]); err != nil {
		logger.Error("miniauth: stopped", "err", err)
		os.Exit(2)
	}
	if err := run(logger, listenAddr(), os.Getenv("MINIAUTH_DATABASE_URL"), os.Getenv("MINIAUTH_ADMIN_TOKEN_SHA256")); err != nil {
		logger.Error("miniauth: stopped", "err", err)
		os.Exit(1)
	}
}

// rejectArgs refuses a CLI command.
// The error MUST NOT include the arguments: they can hold a password or a token.
func rejectArgs(args []string) error {
	if len(args) == 0 {
		return nil
	}
	return errors.New("miniauth: the command only serves HTTP")
}

func listenAddr() string {
	if addr := os.Getenv("MINIAUTH_LISTEN"); addr != "" {
		return addr
	}
	return "127.0.0.1:8080"
}

func publicURL() (api.PublicURL, error) {
	parsed, err := api.ParsePublicURL(os.Getenv("MINIAUTH_PUBLIC_URL"))
	if err != nil {
		return api.PublicURL{}, errors.New("miniauth: MINIAUTH_PUBLIC_URL is not an http or https origin")
	}
	return parsed, nil
}

func sessionDomain() (sessions.Domain, error) {
	domain, err := sessions.ParseDomain(os.Getenv("MINIAUTH_COOKIE_DOMAIN"))
	if err != nil {
		return sessions.Domain{}, errors.New("miniauth: MINIAUTH_COOKIE_DOMAIN is not a valid cookie domain")
	}
	return domain, nil
}

func run(logger *slog.Logger, addr, databaseURL, adminTokenSHA256 string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if databaseURL == "" {
		return errors.New("miniauth: MINIAUTH_DATABASE_URL is not set")
	}
	stopTelemetry, err := telemetry.Install(ctx)
	if err != nil {
		return err
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if stopErr := stopTelemetry(stopCtx); stopErr != nil {
			logger.Error("miniauth: traces", "err", stopErr)
		}
	}()
	adminHash, err := api.ParseAdminTokenHash(adminTokenSHA256)
	if err != nil {
		return errors.New("miniauth: MINIAUTH_ADMIN_TOKEN_SHA256 must be the hex SHA-256 of the admin token")
	}
	pool, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = postgres.Migrate(ctx, pool); err != nil {
		return err
	}
	logger.Info("miniauth: migrations applied")

	domain, err := sessionDomain()
	if err != nil {
		return err
	}
	public, err := publicURL()
	if err != nil {
		return err
	}
	handler, err := api.NewRouter(
		users.NewService(postgres.NewUserRepository(pool)),
		sessions.NewService(postgres.NewSessionRepository(pool)),
		postgres.NewGroupRepository(pool),
		domain,
		public,
		adminHash,
		logger,
	)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("miniauth: listening", "addr", addr)
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("miniauth: serve: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("miniauth: shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("miniauth: serve: %w", err)
	}
	return nil
}
