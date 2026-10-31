package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/config"
	"github.com/popoffvg/miniauth/internal/postgres/postgrestest"
)

func TestReadyzFollowsPostgreSQL(t *testing.T) {
	upstream := postgrestest.NewDatabase(t)
	proxy := startDBProxy(t, upstream)

	ln, err := listenLocal(t.Context())
	require.NoError(t, err)

	cfg, err := config.Load(func(key string) string {
		switch key {
		case "MINIAUTH_LISTEN":
			return ln.Addr().String()
		case "MINIAUTH_DATABASE_URL":
			return proxy.dsn
		case "MINIAUTH_ADMIN_TOKEN_SHA256":
			sum := sha256.Sum256([]byte("bootstrap-token-for-tests"))
			return hex.EncodeToString(sum[:])
		default:
			return ""
		}
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var finished atomic.Pointer[error]
	go func() {
		err := run(ctx, slog.New(slog.DiscardHandler), cfg, ln)
		finished.Store(&err)
	}()

	base := "http://" + ln.Addr().String()
	waitStatus(t, &finished, base+"/readyz", http.StatusOK, 20*time.Second)

	proxy.Stop()
	waitStatus(t, &finished, base+"/readyz", http.StatusServiceUnavailable, 10*time.Second)
	require.Equal(t, http.StatusNoContent, getStatus(t, base+"/healthz"))

	require.NoError(t, proxy.Start(t.Context()))
	waitStatus(t, &finished, base+"/readyz", http.StatusOK, 15*time.Second)

	cancel()
	require.Eventually(t, func() bool { return finished.Load() != nil }, shutdownTimeout+time.Second, 10*time.Millisecond)
	require.NoError(t, *finished.Load())
}

func waitStatus(t *testing.T, finished *atomic.Pointer[error], rawURL string, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last int
	var lastErr error
	for time.Now().Before(deadline) {
		if errp := finished.Load(); errp != nil {
			t.Fatalf("process stopped while waiting for %d: %v", want, *errp)
		}
		status, err := statusOf(t, rawURL)
		last = status
		lastErr = err
		if err == nil && status == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("GET readiness: want %d within %s, last %d, err %v", want, within, last, lastErr)
}

func statusOf(t *testing.T, rawURL string) (int, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// dbProxy forwards TCP to PostgreSQL.
// Stop closes it, which is what the process sees when PostgreSQL stops.
// Start opens it again.
type dbProxy struct {
	addr     string
	upstream string
	dsn      string

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
}

func startDBProxy(t *testing.T, upstreamDSN string) *dbProxy {
	t.Helper()
	upstream, dsn, err := proxyPlan(upstreamDSN)
	require.NoError(t, err)
	ln, err := listenLocal(t.Context())
	require.NoError(t, err)
	proxy := &dbProxy{
		addr:     ln.Addr().String(),
		upstream: upstream,
		ln:       ln,
		conns:    map[net.Conn]struct{}{},
	}
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	parsed.Host = proxy.addr
	proxy.dsn = parsed.String()
	go proxy.serve(t.Context(), ln)
	t.Cleanup(proxy.Stop)
	return proxy
}

func proxyPlan(upstreamDSN string) (upstream, dsn string, err error) {
	parsed, err := url.Parse(upstreamDSN)
	if err != nil {
		return "", "", err
	}
	host := parsed.Host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		host = net.JoinHostPort(host, "5432")
	}
	return host, upstreamDSN, nil
}

func (p *dbProxy) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}
	for conn := range p.conns {
		_ = conn.Close()
	}
	clear(p.conns)
}

func (p *dbProxy) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ln != nil {
		return nil
	}
	var ln net.Listener
	var err error
	for range 5 {
		ln, err = listenOn(ctx, p.addr)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	if err != nil {
		return err
	}
	p.ln = ln
	go p.serve(ctx, ln)
	return nil
}

func listenLocal(ctx context.Context) (net.Listener, error) {
	return listenOn(ctx, "127.0.0.1:0")
}

func listenOn(ctx context.Context, addr string) (net.Listener, error) {
	var listen net.ListenConfig
	return listen.Listen(ctx, "tcp", addr)
}

func (p *dbProxy) serve(ctx context.Context, ln net.Listener) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.ln != ln {
			p.mu.Unlock()
			_ = client.Close()
			return
		}
		p.conns[client] = struct{}{}
		p.mu.Unlock()
		go p.forward(ctx, ln, client)
	}
}

func (p *dbProxy) forward(ctx context.Context, ln net.Listener, client net.Conn) {
	dialer := &net.Dialer{Timeout: time.Second}
	upstream, err := dialer.DialContext(ctx, "tcp", p.upstream)
	if err != nil {
		p.drop(client)
		return
	}
	p.mu.Lock()
	if p.ln != ln {
		p.mu.Unlock()
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	p.conns[upstream] = struct{}{}
	p.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}()
	wg.Wait()
	p.drop(client)
	p.drop(upstream)
}

func (p *dbProxy) drop(conn net.Conn) {
	_ = conn.Close()
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}
