package passwordstep

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// AttemptKind groups the steps that share one failure count per login.
type AttemptKind string

const (
	// KindPassword is a password try.
	KindPassword AttemptKind = "password"
	// KindSecondFactor is a TOTP code or a recovery code. A password success does not reset its count.
	KindSecondFactor AttemptKind = "second_factor"
	// KindRecovery is a password recovery request. Its store keeps no other kind.
	KindRecovery AttemptKind = "recovery"
)

// Attempt is one try of a step. It has no field for the password or the code.
type Attempt struct {
	Kind        AttemptKind
	Login       users.Login
	IP          ClientIP
	Succeeded   bool
	AttemptedAt time.Time
}

// FailureCount is the failed tries of one login or one IP inside BackoffWindow.
// LastFailure is the zero time when Failures is 0.
type FailureCount struct {
	Failures    int
	LastFailure time.Time
}

// RecentFailures is the failure count of the login and of the IP of one try.
type RecentFailures struct {
	Login FailureCount
	IP    FailureCount
}
