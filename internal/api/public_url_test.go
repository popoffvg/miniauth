package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePublicURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		host    string
		wantErr bool
	}{
		{name: "empty"},
		{name: "https origin", raw: "https://id.example.test", host: "id.example.test"},
		{name: "https origin with a slash", raw: "https://id.example.test/", host: "id.example.test"},
		{name: "origin with a port", raw: "http://127.0.0.1:8088", host: "127.0.0.1:8088"},
		{name: "highest port", raw: "https://id.example.test:65535", host: "id.example.test:65535"},
		{name: "port above 65535", raw: "https://id.example.test:99999", wantErr: true},
		{name: "port zero", raw: "https://id.example.test:0", wantErr: true},
		{name: "ipv6 origin", raw: "https://[2001:db8::1]:443", host: "[2001:db8::1]:443"},
		{name: "empty hostname", raw: "https://:443", wantErr: true},
		{name: "path", raw: "https://id.example.test/login", wantErr: true},
		{name: "user info", raw: "https://user:idp_not_a_token@id.example.test/", wantErr: true},
		{name: "query", raw: "https://id.example.test/?return=1", wantErr: true},
		{name: "fragment", raw: "https://id.example.test/#login", wantErr: true},
		{name: "other scheme", raw: "ftp://id.example.test", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePublicURL(tt.raw)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrPublicURL)
				assert.NotContains(t, err.Error(), tt.raw)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.host, got.Host())
		})
	}
}

func TestPublicURLLogin(t *testing.T) {
	origin := mustPublicURL(t, "https://id.example.test")
	assert.Equal(t, "https://id.example.test/login", origin.Login(""))
	assert.Equal(t, "https://id.example.test/login?return=https%3A%2F%2Fapp.example.test%2Fdash%3Fx%3D1", origin.Login("https://app.example.test/dash?x=1"))
	assert.Equal(t, "/login", PublicURL{}.Login(""))
}
