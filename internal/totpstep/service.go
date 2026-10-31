package totpstep

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/passwordstep"
	"github.com/popoffvg/miniauth/internal/users"
)

// Store keeps the TOTP credential and the recovery code hashes of each user.
// SavePending MUST return ErrEnrolled when the user has a confirmed credential.
// Find MUST return ErrNotEnrolled when the user has no row.
// Confirm saves step and replaces the recovery codes in one transaction. It MUST return
// ErrNoEnrollment when no unconfirmed row with createdAt exists.
// UseStep stores step only when it is later than the stored step, and reports whether it did.
// UseRecoveryCode marks an unused code as used, and reports whether it did.
// Delete removes the credential and every recovery code.
type Store interface {
	SavePending(ctx context.Context, userID users.ID, sealed SealedSecret, createdAt time.Time) error
	Find(ctx context.Context, userID users.ID) (Credential, error)
	Confirm(ctx context.Context, userID users.ID, createdAt time.Time, step TimeStep, codes []RecoveryHash, at time.Time) error
	UseStep(ctx context.Context, userID users.ID, step TimeStep) (bool, error)
	UseRecoveryCode(ctx context.Context, userID users.ID, hash RecoveryHash, at time.Time) (bool, error)
	Delete(ctx context.Context, userID users.ID) error
}

// Service enrolls TOTP and checks TOTP codes and recovery codes.
type Service struct {
	store   Store
	limiter *passwordstep.Limiter
	key     Key
	now     func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
// TOTP and recovery code failures share the passwordstep.KindSecondFactor backoff.
func NewService(store Store, attempts passwordstep.AttemptStore, key Key) (*Service, error) {
	return NewServiceWithClock(store, attempts, key, time.Now)
}

// NewServiceWithClock is NewService with the clock read from now.
func NewServiceWithClock(store Store, attempts passwordstep.AttemptStore, key Key, now func() time.Time) (*Service, error) {
	if store == nil || now == nil {
		return nil, errors.New("totpstep: store or clock is missing")
	}
	limiter, err := passwordstep.NewLimiter(attempts, passwordstep.KindSecondFactor)
	if err != nil {
		return nil, err
	}
	return &Service{store: store, limiter: limiter, key: key, now: now}, nil
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
	secret, err := NewSecret()
	if err != nil {
		return Enrollment{}, err
	}
	sealed, err := s.key.seal(secret, user.ID)
	if err != nil {
		return Enrollment{}, err
	}
	if err := s.store.SavePending(ctx, user.ID, sealed, s.clock()); err != nil {
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
	if err := s.store.Confirm(ctx, userID, credential.CreatedAt, step, hashes, now); err != nil {
		return nil, err
	}
	return codes, nil
}

// Disable removes the TOTP and the recovery codes of userID.
func (s *Service) Disable(ctx context.Context, userID users.ID) error {
	return s.store.Delete(ctx, userID)
}

// VerifyCode checks a TOTP code of user and sends EventStepPassed or EventStepFailed to flow.
// A code of a step that was accepted before fails. It returns ErrWrongCode on a failure,
// and a *passwordstep.TooSoonError without a check while the backoff lasts.
func (s *Service) VerifyCode(ctx context.Context, flow passwordstep.Flow, user users.User, code Code, ip passwordstep.ClientIP) error {
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
func (s *Service) VerifyRecoveryCode(ctx context.Context, flow passwordstep.Flow, user users.User, code RecoveryCode, ip passwordstep.ClientIP) error {
	return s.verify(ctx, flow, user, ip, loginflow.FactorRecovery, func(now time.Time) (bool, error) {
		return s.store.UseRecoveryCode(ctx, user.ID, code.Hash(), now)
	})
}

// verify runs check inside the backoff, records the attempt, and applies the event of factor.
func (s *Service) verify(ctx context.Context, flow passwordstep.Flow, user users.User, ip passwordstep.ClientIP, factor loginflow.Factor, check func(now time.Time) (bool, error)) error {
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
		return fmt.Errorf("totpstep: apply %s: %w", event.Kind, err)
	}
	if !passed {
		return ErrWrongCode
	}
	return nil
}

// pending returns the unconfirmed credential of userID that has not expired.
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
		return Credential{}, ErrNoEnrollment
	}
	return credential, nil
}

// clock returns UTC truncated to microseconds, the precision of a PostgreSQL timestamp.
// Confirm finds the enrollment by its created_at, so the stored value MUST equal the read one.
func (s *Service) clock() time.Time {
	return s.now().UTC().Truncate(time.Microsecond)
}
