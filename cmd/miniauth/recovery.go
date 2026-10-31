package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/config"
	"github.com/popoffvg/miniauth/internal/mailer"
	"github.com/popoffvg/miniauth/internal/postgres"
	"github.com/popoffvg/miniauth/internal/recovery"
)

// mailSender is the adapter that cfg names, or nil when mail is off.
func mailSender(cfg config.Mail) recovery.Mailer {
	switch cfg.Kind {
	case config.MailSMTP:
		return mailer.NewSMTPMailer(cfg.SMTP)
	case config.MailLog:
		return mailer.NewLogMailer(os.Stderr)
	default:
		return nil
	}
}

// startRecovery returns the router option and a stop function that waits for the mail worker.
// With mail off, the option sets no service and the recovery routes answer 503.
func startRecovery(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (api.RouterOption, func(), error) {
	sender := mailSender(cfg.Mail)
	if sender == nil {
		return api.WithRecovery(nil), func() {}, nil
	}
	svc, err := recovery.NewService(
		postgres.NewPasswordResetRepository(pool),
		postgres.NewRecoveryAttemptRepository(pool),
		sender,
		cfg.PublicURL,
	)
	if err != nil {
		return nil, nil, err
	}
	// The worker outlives the signal context, so a mail queued during the drain still goes out.
	workerCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Run(workerCtx, logger)
	}()
	stop := func() {
		cancel()
		<-done
	}
	return api.WithRecovery(svc), stop, nil
}
