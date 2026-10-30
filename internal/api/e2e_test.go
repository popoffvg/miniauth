package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestCreateUserHurl(t *testing.T) {
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("docker is not available")
	}
	t.Logf("gofakeit seed %d", fakeSeed+2)
	fake := gofakeit.New(fakeSeed + 2)
	login := fake.Regex(`[a-z][a-z0-9]{7}`)
	password := fake.Password(true, true, true, false, false, 20)
	token, hash := randomAdminToken(t)

	ctx := t.Context()
	nw, err := network.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = nw.Remove(context.WithoutCancel(ctx))
	})

	pg, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("miniauth"),
		postgres.WithUsername("miniauth"),
		postgres.WithPassword("miniauth"),
		network.WithNetwork([]string{"postgres"}, nw),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = pg.Terminate(context.WithoutCancel(ctx))
	})

	root := repoRoot(t)
	app, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    root,
				Dockerfile: "Dockerfile",
				KeepImage:  true,
			},
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"MINIAUTH_LISTEN":             "0.0.0.0:8080",
				"MINIAUTH_DATABASE_URL":       "postgres://miniauth:miniauth@postgres:5432/miniauth?sslmode=disable",
				"MINIAUTH_ADMIN_TOKEN_SHA256": hash,
			},
			Networks:       []string{nw.Name},
			NetworkAliases: map[string][]string{nw.Name: {"miniauth"}},
			WaitingFor: wait.ForHTTP("/healthz").
				WithPort("8080/tcp").
				WithStatusCodeMatcher(func(status int) bool { return status == 204 }).
				WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = app.Terminate(context.WithoutCancel(ctx))
	})

	hurl, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: "ghcr.io/orange-opensource/hurl:6.1.1",
			Cmd: []string{
				"--variable", "host=http://miniauth:8080",
				"--variable", "token=" + token,
				"--variable", "login=" + login,
				"--variable", "password=" + password,
				"/scenario/create_user.hurl",
			},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      filepath.Join(root, "testdata", "create_user.hurl"),
				ContainerFilePath: "/scenario/create_user.hurl",
				FileMode:          0o444,
			}},
			Networks:   []string{nw.Name},
			WaitingFor: wait.ForExit().WithExitTimeout(time.Minute),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = hurl.Terminate(context.WithoutCancel(ctx))
	})

	state, err := hurl.State(ctx)
	require.NoError(t, err)
	if state.ExitCode != 0 {
		logs, logErr := hurl.Logs(ctx)
		require.NoError(t, logErr)
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(logs)
		text := buf.String()
		text = strings.ReplaceAll(text, token, "redacted")
		text = strings.ReplaceAll(text, password, "redacted")
		t.Log(text)
	}
	require.Equal(t, 0, state.ExitCode)
}

func randomAdminToken(t *testing.T) (token, hashHex string) {
	t.Helper()
	var raw [32]byte
	_, err := rand.Read(raw[:])
	require.NoError(t, err)
	token = hex.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:])
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
