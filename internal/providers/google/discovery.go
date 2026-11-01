package google

import (
	"context"
	"fmt"
	"time"

	"github.com/avast/retry-go"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/popoffvg/sfsm"
)

const (
	// DiscoveryInterval is the pause between two discovery requests.
	DiscoveryInterval = 10 * time.Minute
	// discoveryTimeout is how long one discovery request may run.
	discoveryTimeout = 10 * time.Second
)

// Availability is whether the step can send a browser to Google.
type Availability string

const (
	// AvailabilityUnknown is the state before the first discovery.
	AvailabilityUnknown Availability = "unknown"
	// AvailabilityUp means the last discovery succeeded.
	AvailabilityUp Availability = "up"
	// AvailabilityDown means the last discovery failed.
	AvailabilityDown Availability = "down"
)

// discoveryEvent is the result of one discovery request.
type discoveryEvent bool

const (
	discovered      discoveryEvent = true
	discoveryFailed discoveryEvent = false
)

// nextAvailability is the policy: the last discovery decides.
func nextAvailability(_ Availability, event discoveryEvent) (Availability, error) {
	if event == discovered {
		return AvailabilityUp, nil
	}
	return AvailabilityDown, nil
}

// Watch runs discovery now and then once per every, until ctx is done or the step is closed.
// A success replaces the provider endpoints. The key set refreshes on demand inside go-oidc.
func (s *Step) Watch(ctx context.Context, every time.Duration) {
	sfsm.ObserveExternalState(ctx, s.availability, func(ctx context.Context) discoveryEvent {
		probe, cancel := context.WithTimeout(ctx, discoveryTimeout)
		defer cancel()
		provider, err := oidc.NewProvider(oidc.ClientContext(probe, s.client), string(s.config.Issuer))
		if err != nil {
			s.logger.WarnContext(ctx, "google: discovery failed", "err", err)
			return discoveryFailed
		}
		s.provider.Store(provider)
		return discovered
	}, retry.Delay(every), retry.DelayType(retry.FixedDelay))
}

// Available reports whether the last discovery succeeded.
func (s *Step) Available() bool {
	return s.availability.Get() == AvailabilityUp
}

// Close stops the availability machine and Watch.
func (s *Step) Close() error {
	if err := s.availability.Close(); err != nil {
		return fmt.Errorf("google: close: %w", err)
	}
	return nil
}
