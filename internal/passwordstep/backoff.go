package passwordstep

import "time"

const (
	// BackoffWindow is how far back a failed try counts.
	BackoffWindow = 15 * time.Minute
	// FreeFailures is how many failures in BackoffWindow cost no wait.
	FreeFailures = 5
	// FirstDelay is the wait after failure FreeFailures. Each next failure doubles it.
	FirstDelay = time.Second
	// MaxDelay caps the wait. There is no hard lock.
	MaxDelay = time.Minute
)

// BackoffDelay is the wait after the last of failures failed tries.
func BackoffDelay(failures int) time.Duration {
	if failures < FreeFailures {
		return 0
	}
	delay := FirstDelay
	for i := FreeFailures; i < failures && delay < MaxDelay; i++ {
		delay *= 2
	}
	return min(delay, MaxDelay)
}

// ReadyAt is the earliest time this count accepts a next try.
func (c FailureCount) ReadyAt() time.Time {
	return c.LastFailure.Add(BackoffDelay(c.Failures))
}

// ReadyAt is the later ReadyAt of the login and the IP.
func (r RecentFailures) ReadyAt() time.Time {
	login, ip := r.Login.ReadyAt(), r.IP.ReadyAt()
	if login.After(ip) {
		return login
	}
	return ip
}
