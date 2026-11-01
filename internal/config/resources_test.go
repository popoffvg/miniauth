package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
)

func TestLoadResources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resources.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"resources": [
		{"name": "Dashboards", "url": "https://dash.example.test/", "groups": ["users", "Ops", "ops"]},
		{"name": "wiki", "url": "https://wiki.example.test/docs", "groups": []}
	]}`), 0o600))
	entries, err := loadResources(path)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "dashboards", entries[0].Name.String())
	assert.Equal(t, "dash.example.test/", entries[0].URL.String())
	assert.Equal(t, []string{"users", "ops"}, groupStrings(entries[0].Groups))
	assert.Empty(t, entries[1].Groups)

	none, err := loadResources("")
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestLoadResourcesRefusesABadFile(t *testing.T) {
	const secret = "s3cret-in-the-file"
	tests := []struct {
		name    string
		body    string
		want    error
		message string
	}{
		{name: "not JSON", body: `{"resources": [` + secret, want: errResourcesJSON, message: "MINIAUTH_RESOURCES_FILE is not a JSON object"},
		{name: "no array", body: `{"items": []}`, want: errResourcesJSON, message: "MINIAUTH_RESOURCES_FILE"},
		{name: "bad URL", body: `{"resources": [{"name": "a", "url": "https://a.example.test/"}, {"name": "b", "url": "ftp://` + secret + `@b.example.test/"}]}`, want: access.ErrResourceURL, message: "MINIAUTH_RESOURCES_FILE: resources[1]"},
		{name: "bad group", body: `{"resources": [{"name": "a", "url": "https://a.example.test/", "groups": ["-` + secret + `"]}]}`, want: groups.ErrName, message: "resources[0]"},
		{name: "unknown field", body: `{"resources": [{"name": "a", "url": "https://a.example.test/", "` + secret + `": 1}]}`, want: errEntry, message: "resources[0]"},
		{name: "no URL", body: `{"resources": [{"name": "a"}]}`, want: errEntryURL, message: "resources[0]"},
		{name: "no name", body: `{"resources": [{"url": "https://a.example.test/"}]}`, want: errEntryName, message: "resources[0]"},
		{name: "repeated name", body: `{"resources": [{"name": "a", "url": "https://a.example.test/"}, {"name": "A", "url": "https://b.example.test/"}]}`, want: errEntryRepeat, message: "resources[1]"},
		{name: "repeated URL", body: `{"resources": [{"name": "a", "url": "https://a.example.test/"}, {"name": "b", "url": "https://a.example.test/"}]}`, want: errEntryRepeat, message: "resources[1]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resources.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.body), 0o600))
			_, err := loadResources(path)
			require.ErrorIs(t, err, tt.want)
			assert.Contains(t, err.Error(), tt.message)
			assert.NotContains(t, err.Error(), secret)
		})
	}

	_, err := loadResources(filepath.Join(t.TempDir(), "missing.json"))
	require.ErrorIs(t, err, errResourcesRead)
}

func TestLoadStopsOnABadResourcesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resources.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"resources": [{"name": "a"}]}`), 0o600))
	hash := adminHash(t, "bootstrap-token")
	_, err := Load(func(key string) string {
		switch key {
		case envDatabase:
			return "postgres://miniauth@127.0.0.1:5432/miniauth"
		case envAdmin:
			return hash
		case envResources:
			return path
		default:
			return ""
		}
	})
	require.ErrorIs(t, err, errEntryURL)
	assert.Contains(t, err.Error(), "MINIAUTH_RESOURCES_FILE: resources[0]")
}

func groupStrings(names []groups.Name) []string {
	found := make([]string, 0, len(names))
	for _, name := range names {
		found = append(found, name.String())
	}
	return found
}
