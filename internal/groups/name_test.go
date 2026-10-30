package groups

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseName(t *testing.T) {
	long := "a" + strings.Repeat("b", 62) + "c"
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{name: "trimmed and folded", raw: " Editors ", want: "editors"},
		{name: "middle punctuation", raw: "a.b_c-d", want: "a.b_c-d"},
		{name: "longest name", raw: long, want: long},
		{name: "empty", raw: "", wantErr: ErrName},
		{name: "space", raw: "has space", wantErr: ErrName},
		{name: "too long", raw: long + "d", wantErr: ErrName},
		{name: "leading dot", raw: ".editors", wantErr: ErrName},
		{name: "trailing hyphen", raw: "editors-", wantErr: ErrName},
		{name: "non ascii", raw: "éditors", wantErr: ErrName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseName(tt.raw)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}
