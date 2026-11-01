package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExpiryInput(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    time.Time
		never   bool
		wantErr error
	}{
		{name: "empty never expires", raw: " ", never: true},
		{name: "date ends with its UTC day", raw: "2030-05-01", want: time.Date(2030, 5, 2, 0, 0, 0, 0, time.UTC)},
		{name: "datetime-local is UTC", raw: "2030-05-01T13:45", want: time.Date(2030, 5, 1, 13, 45, 0, 0, time.UTC)},
		{name: "datetime-local with seconds", raw: "2030-05-01T13:45:30", want: time.Date(2030, 5, 1, 13, 45, 30, 0, time.UTC)},
		{name: "RFC 3339 is not an HTML value", raw: "2030-05-01T13:45:00Z", wantErr: errExpiryInput},
		{name: "text", raw: "tomorrow", wantErr: errExpiryInput},
		{name: "the zero time is not never", raw: "0001-01-01T00:00", wantErr: errExpiryInput},
		{name: "a date that ends at the zero time", raw: "0000-12-31", wantErr: errExpiryInput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExpiryInput(tt.raw)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			at, expires := got.Time()
			assert.Equal(t, !tt.never, expires)
			assert.True(t, tt.want.Equal(at), at)
		})
	}
}
