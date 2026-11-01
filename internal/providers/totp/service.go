package totp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/password"
	"github.com/popoffvg/miniauth/internal/users"
)

// Store keeps the TOTP credential and the recovery code hashes of each user.
// Find MUST return ErrNotEnrolled when the user has no row.
// Write stores the transition from prev to next. It MUST wrap sfsm.ErrStaleState when the row is no longer
// at prev.Version, and for a confirm also when the row is no longer the pending enrollment of prev.CreatedAt.
// A confirm replaces the recovery codes in the same transaction. A next stage that is not Stored
// deletes the row and every recovery code in one transaction.
// UseStep stores step only when it is later than the stored step, and reports whether it did.
// UseRecoveryCode marks an unused code as used, and reports whether it did.
type Store interface {
	Find(ctx context.Context, userID users.ID) (Credential, error)
	Write(ctx context.Context, userID users.ID, prev, next EnrollmentState) error
	UseStep(ctx context.Context, userID users.ID, step TimeStep) (bool, error)
	UseRecoveryCode(ctx context.Context, userID users.ID, hash RecoveryHash, at time.Time) (bool, error)
}

// Service enrolls TOTP and checks TOTP codes and recovery codes.
type Service struct {
	store   Store
	limiter *password.Limiter
	key     Key
	now     func() time.Time
	logger  *slog.Logger
}

// NewService returns a service that reads the clock from time.Now.
// TOTP and recovery code failures share the password.KindSecondFactor backoff.
// A nil logger discards the enrollment transition log.
func NewService(store Store, attempts password.AttemptStore, key Key, logger *slog.Logger) (*Service, error) {
	return NewServiceWithClock(store, attempts, key, time.Now, logger)
}

// NewServiceWithClock is NewService with the clock read from now.
func NewServiceWithClock(store Store, attempts password.AttemptStore, key Key, now func() time.Time, logger *slog.Logger) (*Service, error) {
	if store == nil || now == nil {
		return nil, errors.New("totp: store or clock is missing")
	}
	limiter, err := password.NewLimiter(attempts, password.KindSecondFactor)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Service{store: store, limiter: limiter, key: key, now: now, logger: logger}, nil
}

var _ loginflow.SecondFactors = (*Service)(nil)

// EnrollmentOn reports whether a user can enroll. It is false without MINIAUTH_TOTP_KEY.
func (s *Service) EnrollmentOn() bool {
	return s.key.Set()
}

// HasSecondFactor reports whether userID has a confirmed TOTP.
func (s *Service) HasSecondFactor(ctx context.Context, userID users.ID) (bool, error) {
	credential, err := s.store.Find(ctx, userID)
	if errors.Is(err, ErrNotEnrolled) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return credential.Confirmed(), nil
}

// Begin makes a new secret for user and stores it sealed until Confirm.
// A later Begin replaces an enrollment that waits.
func (s *Service) Begin(ctx context.Context, user users.User) (Enrollment, error) {
	state, err := s.state(ctx, user.ID)
	if err != nil {
		return Enrollment{}, err
	}
	secret, err := NewSecret()
	if err != nil {
		return Enrollment{}, err
	}
	sealed, err := s.key.seal(secret, user.ID)
	if err != nil {
		return Enrollment{}, err
	}
	err = s.transition(ctx, user.ID, state, EnrollmentEvent{Kind: EventBegin, At: s.clock(), Sealed: sealed})
	if errors.Is(err, ErrNoTransition) {
		return Enrollment{}, ErrEnrolled
	}
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Secret: secret, URI: secret.KeyURI(user.Login)}, nil
}

// Pending returns the enrollment of user that waits for its first code.
func (s *Service) Pending(ctx context.Context, user users.User) (Enrollment, error) {
	credential, err := s.pending(ctx, user.ID)
	if err != nil {
		return Enrollment{}, err
	}
	secret, err := s.key.open(credential.Sealed, user.ID)
	if err != nil {
		return Enrollment{}, err
	}
	return Enrollment{Secret: secret, URI: secret.KeyURI(user.Login)}, nil
}

// Confirm turns on TOTP when code matches the enrollment that waits.
// It returns RecoveryCodeCount recovery codes. They are shown once: only their hashes are stored.
func (s *Service) Confirm(ctx context.Context, userID users.ID, code Code) ([]RecoveryCode, error) {
	credential, err := s.pending(ctx, userID)
	if err != nil {
		return nil, err
	}
	secret, err := s.key.open(credential.Sealed, userID)
	if err != nil {
		return nil, err
	}
	now := s.clock()
	step, ok := secret.Match(code, now, 0)
	if !ok {
		return nil, ErrWrongCode
	}
	codes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	hashes := make([]RecoveryHash, len(codes))
	for i, c := range codes {
		hashes[i] = c.Hash()
	}
	event := EnrollmentEvent{Kind: EventConfirm, At: now, Step: step, RecoveryCodes: hashes}
	if err := s.transition(ctx, userID, credential.state(), event); err != nil {
		return nil, err
	}
	return codes, nil
}

// Disable removes the TOTP and the recovery codes of userID.
// A user without TOTP gets nil: there is nothing to turn off.
func (s *Service) Disable(ctx context.Context, userID users.ID) error {
	state, err := s.state(ctx, userID)
	if err != nil {
		return err
	}
	err = s.transition(ctx, userID, state, EnrollmentEvent{Kind: EventDisable})
	if errors.Is(err, ErrNoTransition) {
		return nil
	}
	return err
}

// VerifyCode checks a TOTP code of user and sends EventStepPassed or EventStepFailed to flow.
// A code of a step that was accepted before fails. It returns ErrWrongCode on a failure,
// and a *password.TooSoonError without a check while the backoff lasts.
func (s *Service) VerifyCode(ctx context.Context, flow password.Flow, user users.User, code Code, ip password.ClientIP) error {
	return s.verify(ctx, flow, user, ip, loginflow.FactorTOTP, func(now time.Time) (bool, error) {
		credential, err := s.store.Find(ctx, user.ID)
		if errors.Is(err, ErrNotEnrolled) || err == nil && !credential.Confirmed() {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		secret, err := s.key.open(credential.Sealed, user.ID)
		if err != nil {
			return false, err
		}
		step, ok := secret.Match(code, now, credential.LastStep)
		if !ok {
			return false, nil
		}
		return s.store.UseStep(ctx, user.ID, step)
	})
}

// VerifyRecoveryCode spends one recovery code of user and reports the result to flow like VerifyCode.
func (s *Service) VerifyRecoveryCode(ctx context.Context, flow password.Flow, user users.User, code RecoveryCode, ip password.ClientIP) error {
	return s.verify(ctx, flow, user, ip, loginflow.FactorRecovery, func(now time.Time) (bool, error) {
		return s.store.UseRecoveryCode(ctx, user.ID, code.Hash(), now)
	})
}

// verify runs check inside the backoff, records the attempt, and applies the event of factor.
func (s *Service) verify(ctx context.Context, flow password.Flow, user users.User, ip password.ClientIP, factor loginflow.Factor, check func(now time.Time) (bool, error)) error {
	now := s.clock()
	if err := s.limiter.Wait(ctx, user.Login, ip, now); err != nil {
		return err
	}
	passed, err := check(now)
	if err != nil {
		return err
	}
	if err := s.limiter.Record(ctx, user.Login, ip, passed, now); err != nil {
		return err
	}
	event := loginflow.Event{Kind: loginflow.EventStepFailed, Factor: factor}
	if passed {
		event.Kind = loginflow.EventStepPassed
		event.UserID = user.ID
	}
	if err := flow.Apply(ctx, event); err != nil {
		return fmt.Errorf("totp: apply %s: %w", event.Kind, err)
	}
	if !passed {
		return ErrWrongCode
	}
	return nil
}

// pending returns the unconfirmed credential of userID that has not expired.
// An expired one is deleted.
func (s *Service) pending(ctx context.Context, userID users.ID) (Credential, error) {
	credential, err := s.store.Find(ctx, userID)
	if errors.Is(err, ErrNotEnrolled) {
		return Credential{}, ErrNoEnrollment
	}
	if err != nil {
		return Credential{}, err
	}
	if credential.Confirmed() {
		return Credential{}, ErrEnrolled
	}
	if !s.clock().Before(credential.CreatedAt.Add(EnrollmentTTL)) {
		if err := s.transition(ctx, userID, credential.state(), EnrollmentEvent{Kind: EventExpire}); err != nil {
			return Credential{}, err
		}
		return Credential{}, ErrNoEnrollment
	}
	return credential, nil
}

// state reads the enrollment stage of userID. No row is StageNone.
func (s *Service) state(ctx context.Context, userID users.ID) (EnrollmentState, error) {
	credential, err := s.store.Find(ctx, userID)
	if errors.Is(err, ErrNotEnrolled) {
		return EnrollmentState{Stage: StageNone}, nil
	}
	if err != nil {
		return EnrollmentState{}, err
	}
	return credential.state(), nil
}

// transition applies event to the state the caller read and checked.
// A lost race with another request is an error that wraps sfsm.ErrStaleState.
func (s *Service) transition(ctx context.Context, userID users.ID, read EnrollmentState, event EnrollmentEvent) error {
	machine, err := sfsm.OpenPersistedSFSM(ctx, enrollmentStore{store: s.store, read: read}, userID, EnrollmentState.apply,
		&sfsm.SFSMOptions[EnrollmentState, EnrollmentEvent]{
			AfterStateChanged: func(from, to EnrollmentState, event EnrollmentEvent) {
				s.logger.InfoContext(ctx, "miniauth: totp enrollment",
					"user", userID,
					"from", from.Stage,
					"to", to.Stage,
					"event", event.Kind,
				)
			},
		})
	if err != nil {
		return fmt.Errorf("totp: open enrollment: %w", err)
	}
	defer func() { _ = machine.Close() }()
	if err := machine.Apply(ctx, event); err != nil {
		return fmt.Errorf("totp: %s: %w", event.Kind, err)
	}
	return nil
}

// enrollmentStore is the sfsm.Store of one transition. Load returns the state the service checked,
// so the version guard of Write refuses the transition when the row moved after that check.
type enrollmentStore struct {
	store Store
	read  EnrollmentState
}

func (e enrollmentStore) Load(context.Context, users.ID) (EnrollmentState, error) {
	return e.read, nil
}

func (e enrollmentStore) Write(ctx context.Context, userID users.ID, prev, next EnrollmentState) error {
	return e.store.Write(ctx, userID, prev, next)
}

// clock returns UTC truncated to microseconds, the precision of a PostgreSQL timestamp.
// Confirm finds the enrollment by its created_at, so the stored value MUST equal the read one.
func (s *Service) clock() time.Time {
	return s.now().UTC().Truncate(time.Microsecond)
}
