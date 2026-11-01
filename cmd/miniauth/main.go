// Command miniauth serves login, sessions, personal access tokens, and the forward-auth check.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/config"
	"github.com/popoffvg/miniauth/internal/groupadmin"
	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/lifecycle"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/providers/google"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/providers/telegram"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/telemetry"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/useradmin"
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
	if err = reconcileResources(ctx, pool, cfg.Resources); err != nil {
		return err
	}
	logger.Info("miniauth: resources file applied", "resources", len(cfg.Resources))
	groups, err := postgres.NewGroupRepository(pool)
	if err != nil {
		return err
	}
	accounts := postgres.NewUserRepository(pool)
	flowStore := postgres.NewFlowStore(pool)
	attempts := postgres.NewAttemptRepository(pool)
	totpService, err := totp.NewService(postgres.NewTOTPRepository(pool), attempts, cfg.TOTPKey)
	if err != nil {
		return err
	}
	passwords, err := password.NewService(accounts, attempts, password.WithSecondFactors(totpService))
	if err != nil {
		return err
	}
	grantRepo, err := postgres.NewAccessRepository(pool)
	if err != nil {
		return err
	}
	userService := users.NewService(accounts)
	grants := access.NewService(grantRepo, userService)

	withRecovery, stopRecovery, err := startRecovery(ctx, cfg, pool, logger)
	if err != nil {
		return err
	}
	defer stopRecovery()
	inviteRepo, err := postgres.NewInviteRepository(pool)
	if err != nil {
		return err
	}
	inviteService, err := invites.NewService(inviteRepo, nil)
	if err != nil {
		return err
	}
	userAdminRepo, err := postgres.NewUserAdminRepository(pool)
	if err != nil {
		return err
	}
	groupAdminRepo, err := postgres.NewGroupAdminRepository(pool)
	if err != nil {
		return err
	}
	groupAdmin, err := groupadmin.NewService(groupAdminRepo, grants)
	if err != nil {
		return err
	}

	options := []api.RouterOption{
		api.WithAccessTokens(tokens.NewService(postgres.NewTokenRepository(pool))),
		api.WithLogin(loginflow.NewLoginFlows(flowStore), passwords),
		api.WithTOTP(totpService),
		api.WithURLGrants(grants),
		api.WithAccessAdmin(grants),
		withRecovery,
		api.WithInvites(inviteService),
		api.WithUserAdmin(useradmin.NewService(userAdminRepo, userService)),
		api.WithGroupAdmin(groupAdmin),
	}
	links := identitylink.NewService(postgres.NewIdentityLinkRepository(pool))
	if cfg.Google.Enabled() {
		googleStep, googleErr := startGoogle(ctx, logger, cfg, accounts, flowStore, totpService)
		if googleErr != nil {
			return googleErr
		}
		defer func() { _ = googleStep.Close() }()
		options = append(options, api.WithGoogle(googleStep, links))
	}
	if cfg.Telegram.Enabled() {
		telegramStep, telegramErr := telegram.NewStep(
			telegram.Config{BotName: cfg.Telegram.Name, BotToken: cfg.Telegram.Token, SecondFactors: totpService},
			accounts,
			postgres.NewTelegramProofRepository(pool),
		)
		if telegramErr != nil {
			return telegramErr
		}
		options = append(options, api.WithTelegram(telegramStep, links))
	}
	if passkeys, ok := passkeyService(cfg, postgres.NewPasskeyRepository(pool), flowStore, logger); ok {
		options = append(options, api.WithPasskeys(passkeys))
	}
	handler, err := api.NewRouter(
		userService,
		sessions.NewService(postgres.NewSessionRepository(pool)),
		groups,
		cfg.Cookie,
		cfg.PublicURL,
		cfg.AdminToken,
		machine,
		logger,
		options...,
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

// reconcileResources makes the managed rows equal to the resources file. An error stops the start.
func reconcileResources(ctx context.Context, pool *pgxpool.Pool, entries []access.PredefinedResource) error {
	store, err := postgres.NewManagedRepository(pool)
	if err != nil {
		return err
	}
	reconciler, err := access.NewReconciler(store)
	if err != nil {
		return err
	}
	if err = reconciler.Reconcile(ctx, entries); err != nil {
		return fmt.Errorf("miniauth: MINIAUTH_RESOURCES_FILE: %w", err)
	}
	return nil
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

// startGoogle builds the Google step and runs its discovery in the background.
// The step is offered only after the first discovery succeeds. Close stops the discovery.
func startGoogle(ctx context.Context, logger *slog.Logger, cfg config.Config, identities google.IdentityStore, challenges loginflow.ChallengeStore, secondFactors loginflow.SecondFactors) (*google.Step, error) {
	step, err := google.NewStep(google.Config{
		Issuer:        google.GoogleIssuer,
		ClientID:      cfg.Google.ID,
		ClientSecret:  cfg.Google.Secret,
		RedirectURL:   google.RedirectURL(cfg.PublicURL.Origin() + api.GoogleCallbackPath),
		SecondFactors: secondFactors,
	}, identities, challenges, logger)
	if err != nil {
		return nil, err
	}
	go step.Watch(ctx, google.DiscoveryInterval)
	return step, nil
}

// passkeyService is false when the public URL gives no relying party id, such as an IP address.
// The passkey routes then answer 503 and the other routes still work.
func passkeyService(cfg config.Config, passkeys passkey.Store, challenges loginflow.ChallengeStore, logger *slog.Logger) (*passkey.Service, bool) {
	origin, err := url.Parse(cfg.PublicURL.Origin())
	if err != nil {
		logger.Warn("miniauth: passkeys are off", "err", err)
		return nil, false
	}
	party, err := passkey.NewRelyingParty(cfg.Cookie, origin)
	if err != nil {
		logger.Warn("miniauth: passkeys are off", "err", err)
		return nil, false
	}
	service, err := passkey.NewService(party, passkeys, challenges)
	if err != nil {
		logger.Warn("miniauth: passkeys are off", "err", err)
		return nil, false
	}
	return service, true
}
