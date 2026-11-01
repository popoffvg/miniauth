package recovery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	// QueueSize bounds the mails that wait for the worker. A request past it sends no mail.
	QueueSize = 64
	// sendTimeout bounds one queued job.
	sendTimeout = 30 * time.Second
)

// Store keeps reset links.
// FindAccount MUST return users.ErrNotFound when no user has the login.
// FindOpen MUST return ErrInvalidToken unless the link is unused, expires after now, and its user is active.
// Redeem MUST do these in one transaction, or none of them: lock the open link, store password,
// mark the link used at now, delete every session of the user, and delete every other open link of the user.
// Redeem returns the user, or ErrInvalidToken when the link is not open.
// Cleanup deletes the links that expired before before.
type Store interface {
	FindAccount(ctx context.Context, login users.Login) (users.User, error)
	Create(ctx context.Context, reset Reset) error
	FindOpen(ctx context.Context, hash TokenHash, now time.Time) (Reset, error)
	Redeem(ctx context.Context, hash TokenHash, password users.PasswordHash, now time.Time) (users.User, error)
	Cleanup(ctx context.Context, before time.Time) error
}

// mailJob is one queued unit of work. It runs on the worker context, not on a request context.
type mailJob func(ctx context.Context) error

// Service sends reset links and sets a new password through one.
type Service struct {
	store   Store
	limiter *password.Limiter
	mailer  Mailer
	links   Links
	now     func() time.Time
	jobs    chan mailJob
}

// Option changes a Service.
type Option func(*Service)

// WithClock replaces time.Now.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		s.now = now
	}
}

// NewService returns a service with an empty queue. Run MUST run for a mail to go out.
// attempts keeps the recovery requests; the password step backoff applies to them.
func NewService(store Store, attempts password.AttemptStore, mailer Mailer, links Links, options ...Option) (*Service, error) {
	if store == nil || attempts == nil || mailer == nil || links == nil {
		return nil, errors.New("recovery: store, attempt store, mailer, or links is missing")
	}
	limiter, err := password.NewLimiter(attempts, password.KindRecovery)
	if err != nil {
		return nil, err
	}
	s := &Service{
		store:   store,
		limiter: limiter,
		mailer:  mailer,
		links:   links,
		now:     time.Now,
		jobs:    make(chan mailJob, QueueSize),
	}
	for _, option := range options {
		option(s)
	}
	return s, nil
}

// Run sends the queued mails one at a time until ctx ends. Jobs still in the queue are dropped.
// A failed job is logged; the error MUST NOT hold a token, and it does not.
func (s *Service) Run(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-s.jobs:
			jobCtx, cancel := context.WithTimeout(ctx, sendTimeout)
			if err := job(jobCtx); err != nil {
				logger.ErrorContext(ctx, "miniauth: recovery mail", "err", err)
			}
			cancel()
		}
	}
}

// Request queues a reset link for email.
// The reply is the same for a known and an unknown address: the lookup runs in the queue.
// It returns a *password.TooSoonError while the backoff of the address or of ip lasts,
// and ErrQueueFull when the queue has no free slot.
func (s *Service) Request(ctx context.Context, email users.Email, ip password.ClientIP) error {
	if email == (users.Email{}) {
		return users.ErrInvalidLogin
	}
	if ip == (password.ClientIP{}) {
		return password.ErrInvalidClientIP
	}
	now := s.clock()
	if err := s.limiter.Wait(ctx, email.Login(), ip, now); err != nil {
		return err
	}
	// Each request counts as a failure, so the backoff bounds the mails per address and per IP.
	if err := s.limiter.Record(ctx, email.Login(), ip, false, now); err != nil {
		return err
	}
	return s.enqueue(func(ctx context.Context) error {
		return s.sendLink(ctx, email)
	})
}

// Check returns ErrInvalidToken unless token is an open link.
func (s *Service) Check(ctx context.Context, token Token) error {
	_, err := s.findOpen(ctx, token, s.clock())
	return err
}

// Reset stores password for the user of token, signs the user out everywhere, and closes every open link of the user.
// Personal access tokens stay valid. A "password changed" mail is queued.
func (s *Service) Reset(ctx context.Context, token Token, password users.Password) error {
	now := s.clock()
	if _, err := s.findOpen(ctx, token, now); err != nil {
		return err
	}
	hash, err := users.HashPassword(password)
	if err != nil {
		return err
	}
	account, err := s.store.Redeem(ctx, token.Hash(), hash, now)
	if err != nil {
		return err
	}
	email, ok := account.Login.Email()
	if !ok {
		return nil
	}
	if err := s.enqueue(func(ctx context.Context) error {
		return s.mailer.Send(ctx, changedMail(email, s.links.TokensPage()))
	}); err != nil {
		return fmt.Errorf("recovery: password changed, mail not queued: %w", err)
	}
	return nil
}

// findOpen looks the link up by hash and then compares the hash in constant time.
func (s *Service) findOpen(ctx context.Context, token Token, now time.Time) (Reset, error) {
	if token == (Token{}) {
		return Reset{}, ErrInvalidToken
	}
	reset, err := s.store.FindOpen(ctx, token.Hash(), now)
	if err != nil {
		return Reset{}, err
	}
	if !token.Matches(reset.Hash) {
		return Reset{}, ErrInvalidToken
	}
	return reset, nil
}

// sendLink sends no mail for an unknown or disabled account.
func (s *Service) sendLink(ctx context.Context, email users.Email) error {
	now := s.clock()
	if err := s.store.Cleanup(ctx, now); err != nil {
		return err
	}
	account, err := s.store.FindAccount(ctx, email.Login())
	if errors.Is(err, users.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if account.Disabled() {
		return nil
	}
	token, err := NewToken()
	if err != nil {
		return err
	}
	reset := Reset{Hash: token.Hash(), UserID: account.ID, CreatedAt: now, ExpiresAt: now.Add(LinkLifetime)}
	if err := s.store.Create(ctx, reset); err != nil {
		return err
	}
	return s.mailer.Send(ctx, linkMail(email, s.links.ResetLink(token)))
}

func (s *Service) enqueue(job mailJob) error {
	select {
	case s.jobs <- job:
		return nil
	default:
		return ErrQueueFull
	}
}

// clock returns UTC truncated to microseconds. PostgreSQL timestamptz stores microseconds.
func (s *Service) clock() time.Time {
	return s.now().UTC().Truncate(time.Microsecond)
}
