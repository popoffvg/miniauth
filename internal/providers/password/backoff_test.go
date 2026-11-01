package password

import (
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: 0},
		{failures: 4, want: 0},
		{failures: 5, want: time.Second},
		{failures: 6, want: 2 * time.Second},
		{failures: 7, want: 4 * time.Second},
		{failures: 10, want: 32 * time.Second},
		{failures: 11, want: time.Minute},
		{failures: 1000, want: time.Minute},
	}
	for _, tt := range tests {
		if got := BackoffDelay(tt.failures); got != tt.want {
			t.Errorf("BackoffDelay(%d) = %s, want %s", tt.failures, got, tt.want)
		}
	}
}

func TestRecentFailuresReadyAt(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		recent RecentFailures
		want   time.Time
	}{
		{
			name: "no failures",
			want: time.Time{},
		},
		{
			name:   "four login failures cost no wait",
			recent: RecentFailures{Login: FailureCount{Failures: 4, LastFailure: now}},
			want:   now,
		},
		{
			name:   "five login failures wait one second",
			recent: RecentFailures{Login: FailureCount{Failures: 5, LastFailure: now}},
			want:   now.Add(time.Second),
		},
		{
			name:   "five IP failures wait one second",
			recent: RecentFailures{IP: FailureCount{Failures: 5, LastFailure: now}},
			want:   now.Add(time.Second),
		},
		{
			name: "the later of login and IP wins",
			recent: RecentFailures{
				Login: FailureCount{Failures: 7, LastFailure: now.Add(-time.Second)},
				IP:    FailureCount{Failures: 5, LastFailure: now},
			},
			want: now.Add(3 * time.Second),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.recent.ReadyAt(); !got.Equal(tt.want) {
				t.Fatalf("ReadyAt() = %s, want %s", got, tt.want)
			}
		})
	}
}
