// Command miniauth serves login, sessions, personal access tokens, and the forward-auth check.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/config"
	"github.com/popoffvg/miniauth/internal/lifecycle"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/telemetry"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

const shutdownTimeout = 10 * time.Second

// The lifecycle machine is the readiness source for GET /readyz.
var _ api.Readiness = (*lifecycle.Machine)(nil)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := rejectArgs(os.Args[1:]); err != nil {
		logger.Error("miniauth: stopped", "err", err)
		os.Exit(2)
	}
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logger.Error("miniauth: stopped", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var listen net.ListenConfig
	ln, err := listen.Listen(ctx, "tcp", cfg.Listen.String())
	if err != nil {
		stop()
		logger.Error("miniauth: stopped", "err", err)
		os.Exit(1)
	}
	err = run(ctx, logger, cfg, ln)
	stop()
	if err != nil {
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

func run(ctx context.Context, logger *slog.Logger, cfg config.Config, ln net.Listener) error {
	defer func() { _ = ln.Close() }()

	machine := lifecycle.New(logger)
	defer func() { _ = machine.Close() }()

	stopTelemetry, err := telemetry.Install(ctx)
	if err != nil {
		return err
	}
	defer stopTraces(ctx, stopTelemetry, logger)

	pool, err := postgres.Open(ctx, cfg.Database.DSN())
	if err != nil {
		return err
	}
	defer pool.Close()

	watchCtx, stopWatch := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		machine.WatchDatabase(watchCtx, func(ctx context.Context) error {
			return postgres.Probe(ctx, pool)
		}, lifecycle.ProbeInterval)
	}()
	defer func() {
		stopWatch()
		timer := time.NewTimer(lifecycle.ProbeTimeout)
		defer timer.Stop()
		select {
		case <-watchDone:
		case <-timer.C:
			logger.Error("miniauth: database probe did not stop")
		}
	}()

	if err = machine.BeginMigration(ctx); err != nil {
		return err
	}
	if err = postgres.Migrate(ctx, pool); err != nil {
		return err
	}
	logger.Info("miniauth: migrations applied")
	if err = machine.MigrationDone(ctx); err != nil {
		return err
	}
	groups, err := postgres.NewGroupRepository(pool)
	if err != nil {
		return err
	}
	accounts := postgres.NewUserRepository(pool)
	passwords, err := passwordstep.NewService(accounts, postgres.NewAttemptRepository(pool))
	if err != nil {
		return err
	}

	handler, err := api.NewRouter(
		users.NewService(accounts),
		sessions.NewService(postgres.NewSessionRepository(pool)),
		groups,
		cfg.Cookie,
		cfg.PublicURL,
		cfg.AdminToken,
		machine,
		logger,
		api.WithAccessTokens(tokens.NewService(postgres.NewTokenRepository(pool))),
		api.WithLogin(loginflow.NewLoginFlows(postgres.NewFlowStore(pool)), passwords),
	)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("miniauth: listening", "addr", ln.Addr().String())
		serveErr <- server.Serve(ln)
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("miniauth: serve: %w", err)
	case <-ctx.Done():
	}

	// The signal already cancelled ctx. Shutdown needs a fresh deadline.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	return stopServing(shutdownCtx, machine, server, serveErr)
}

func stopTraces(ctx context.Context, stop func(context.Context) error, logger *slog.Logger) {
	stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := stop(stopCtx); err != nil {
		logger.Error("miniauth: traces", "err", err)
	}
}

// stopServing moves the process to Draining and then shuts down the HTTP server.
// Drain runs first, so /readyz returns 503 while open requests finish.
func stopServing(ctx context.Context, machine *lifecycle.Machine, server *http.Server, serveErr <-chan error) error {
	if err := machine.Drain(ctx); err != nil {
		shutErr := server.Shutdown(ctx)
		return fmt.Errorf("miniauth: drain: %w", errors.Join(err, shutErr))
	}
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("miniauth: shutdown: %w", err)
	}
	if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("miniauth: serve: %w", err)
	}
	return nil
}
