package passwordstep

import (
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// Attempt is one password try. It has no field for the password.
type Attempt struct {
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
