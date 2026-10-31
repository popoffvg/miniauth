package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAdminTokenHash(t *testing.T) {
	sum := sha256.Sum256([]byte("bootstrap-token"))
	encoded := hex.EncodeToString(sum[:])
	hash, err := ParseAdminTokenHash(strings.ToUpper(encoded))
	require.NoError(t, err)
	assert.True(t, hash.Matches(BearerToken{raw: "bootstrap-token"}))
	assert.False(t, hash.Matches(BearerToken{raw: "other-token"}))
	assert.Equal(t, "redacted", fmt.Sprint(hash))
	assert.NotContains(t, fmt.Sprintf("%#v", hash), encoded)
	for _, bad := range []string{"", "abcd", encoded + "aa", "zz" + encoded[2:]} {
		_, err := ParseAdminTokenHash(bad)
		assert.Error(t, err)
	}
}

func TestBearerTokenPrintsRedacted(t *testing.T) {
	token := BearerToken{raw: "bootstrap-token"}
	printed := []string{
		fmt.Sprint(token),
		fmt.Sprintf("%v", token),
		fmt.Sprintf("%s", token),
		fmt.Sprintf("%#v", token),
		fmt.Sprintf("%x", token),
		token.String(),
		token.GoString(),
	}
	for _, text := range printed {
		assert.Equal(t, "redacted", text)
		assert.NotContains(t, text, "bootstrap")
	}
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("token", "value", token)
	assert.NotContains(t, logs.String(), "bootstrap")
	assert.Contains(t, logs.String(), "redacted")
}

func TestBearerTokenSchemeIgnoresCase(t *testing.T) {
	for header, want := range map[string]bool{
		"Bearer secret-token": true,
		"bearer secret-token": true,
		"BEARER secret-token": true,
		"Basic secret-token":  false,
		"Bearer":              false,
		"Bearer a b":          false,
	} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		r.Header.Set("Authorization", header)
		token, ok := bearerToken(r)
		assert.Equal(t, want, ok, header)
		if want {
			assert.Equal(t, "secret-token", token.raw, header)
		}
	}
}
