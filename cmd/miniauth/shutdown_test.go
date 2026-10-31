package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/lifecycle"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestDrainMakesReadyz503BeforeShutdown(t *testing.T) {
	machine := lifecycle.New(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	ctx := t.Context()
	require.NoError(t, machine.BeginMigration(ctx))
	require.NoError(t, machine.MigrationDone(ctx))

	handler := readyHandler(t, machine)
	ln, err := listenLocal(t.Context())
	require.NoError(t, err)
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()

	base := "http://" + ln.Addr().String()
	require.Equal(t, http.StatusOK, getStatus(t, base+"/readyz"))

	require.NoError(t, machine.Drain(ctx))
	require.Equal(t, lifecycle.StateDraining, machine.State())
	require.Equal(t, http.StatusServiceUnavailable, getStatus(t, base+"/readyz"))
	require.Equal(t, http.StatusNoContent, getStatus(t, base+"/healthz"))

	shutdownCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	require.NoError(t, server.Shutdown(shutdownCtx))
	require.ErrorIs(t, <-serveErr, http.ErrServerClosed)
}

func TestStopDrainsBeforeShutdown(t *testing.T) {
	machine := lifecycle.New(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { require.NoError(t, machine.Close()) })
	ctx := t.Context()
	require.NoError(t, machine.BeginMigration(ctx))
	require.NoError(t, machine.MigrationDone(ctx))

	entered := make(chan struct{})
	release := make(chan struct{})
	var sawReady atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/block", func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		sawReady.Store(machine.Ready())
		w.WriteHeader(http.StatusNoContent)
	})

	ln, err := listenLocal(t.Context())
	require.NoError(t, err)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(ln) }()

	reqCtx, reqCancel := context.WithCancel(ctx)
	defer reqCancel()
	go func() {
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://"+ln.Addr().String()+"/block", nil)
		if reqErr != nil {
			return
		}
		resp, reqErr := http.DefaultClient.Do(req)
		if reqErr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("the request did not enter the handler")
	}

	stopErr := make(chan error, 1)
	go func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		stopErr <- stopServing(stopCtx, machine, server, serveErr)
	}()

	require.Eventually(t, func() bool {
		return machine.State() == lifecycle.StateDraining
	}, time.Second, 5*time.Millisecond)
	close(release)

	require.NoError(t, <-stopErr)
	assert.False(t, sawReady.Load())
	assert.Equal(t, lifecycle.StateDraining, machine.State())
}

func readyHandler(t *testing.T, ready api.Readiness) http.Handler {
	t.Helper()
	sum := adminHashHex()
	hash, err := api.ParseAdminTokenHash(sum)
	require.NoError(t, err)
	handler, err := api.NewRouter(
		users.NewService(nil),
		sessions.NewService(nil),
		nil,
		sessions.Domain{},
		api.PublicURL{},
		hash,
		ready,
		slog.New(slog.DiscardHandler),
	)
	require.NoError(t, err)
	return handler
}

func adminHashHex() string {
	return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

func getStatus(t *testing.T, rawURL string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
