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

	"github.com/popoffvg/miniauth/internal/postgres"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if len(os.Args) > 1 {
		os.Exit(runAdmin())
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger, listenAddr(), os.Getenv("MINIAUTH_DATABASE_URL")); err != nil {
		logger.Error("miniauth: stopped", "err", err)
		os.Exit(1)
	}
}

func runAdmin() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := runCLI(ctx, os.Args[1:], os.Getenv("MINIAUTH_DATABASE_URL"), os.Stdin, os.Stdout)
	if err != nil && !errors.Is(err, errHelp) {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return 1
	}
	return 0
}

func listenAddr() string {
	if addr := os.Getenv("MINIAUTH_LISTEN"); addr != "" {
		return addr
	}
	return "127.0.0.1:8080"
}

func run(logger *slog.Logger, addr, databaseURL string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if databaseURL == "" {
		return errors.New("miniauth: MINIAUTH_DATABASE_URL is not set")
	}
	pool, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool); err != nil {
		return err
	}
	logger.Info("miniauth: migrations applied")

	server := &http.Server{
		Addr:              addr,
		Handler:           newMux(),
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

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
