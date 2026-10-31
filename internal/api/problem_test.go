package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeJSONRefusesTrailingData(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}
	for raw, ok := range map[string]bool{
		`{"name":"ada"}`:               true,
		"{\"name\":\"ada\"}\n \t":      true,
		`{"name":"ada"}]`:              false,
		`{"name":"ada"}}`:              false,
		`{"name":"ada"}{"name":"bob"}`: false,
		`{"name":"ada"} x`:             false,
	} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		got, err := decodeJSON[body](httptest.NewRecorder(), r, 1<<10)
		if ok {
			require.NoError(t, err, raw)
			assert.Equal(t, "ada", got.Name)
			continue
		}
		require.ErrorIs(t, err, errBadJSON, raw)
	}
}
