package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	hurlImage = "ghcr.io/orange-opensource/hurl:6.1.1"
	// scenarioOrigin is MINIAUTH_PUBLIC_URL of the image. No DNS name resolves it: hurl sends it only in
	// Origin and X-Forwarded-Host. The cookie domain is empty, so each protected URL is on this host too.
	scenarioOrigin     = "https://id.example.test"
	scenarioPublicHost = "id.example.test"
	// runIDLength keeps idp_ + run id + padding at 43 base62 characters in tokens.hurl.
	// A run id is lower-case base32, so it is a valid login part and valid base62.
	runIDLength = 12
)

// scenarioFollowUp is a second hurl file that runs after its scenario with one more variable.
// The runner reads the value from the log of the image, because hurl cannot read a container log.
type scenarioFollowUp struct {
	file     string
	variable string
	read     func(t *testing.T, app testcontainers.Container, run string) string
}

// scenarioFollowUps is keyed by the scenario file. A follow-up file is not a scenario of its own.
// recovery.hurl asks for a reset link; MINIAUTH_MAIL=log writes the mail with the link to the log.
var scenarioFollowUps = map[string]scenarioFollowUp{
	"recovery.hurl": {file: "recovery_reset.hurl", variable: "reset_token", read: resetTokenFromLog},
}

// TestScenarios starts the image once and runs each testdata/scenarios/*.hurl file as a subtest.
// Each subtest gets its own run id, so the logins and resources of two files never meet.
// Every hurl run shares the network namespace of the app, so it calls http://localhost:8080:
// curl keeps a Secure cookie for localhost only, and the session cookies are Secure.
// All files share the client IP 127.0.0.1. The IP backoff of the password step
// counts the wrong passwords of every file together, so the files keep that sum under 5.
func TestScenarios(t *testing.T) {
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skip("docker is not available")
	}
	root := repoRoot(t)
	files, err := filepath.Glob(filepath.Join(root, "testdata", "scenarios", "*.hurl"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	slices.Sort(files)

	adminToken, hash := randomAdminToken(t)
	app := startScenarioApp(t, root, hash)
	followUpFiles := make(map[string]bool, len(scenarioFollowUps))
	for _, followUp := range scenarioFollowUps {
		followUpFiles[followUp.file] = true
	}
	for _, file := range files {
		name := filepath.Base(file)
		if followUpFiles[name] {
			continue
		}
		t.Run(strings.TrimSuffix(name, ".hurl"), func(t *testing.T) {
			run := randomRunID()
			vars := map[string]string{
				"host":        "http://localhost:8080",
				"origin":      scenarioOrigin,
				"public_host": scenarioPublicHost,
				"admin_token": adminToken,
				"run":         run,
			}
			runHurl(t, app, file, vars)
			followUp, ok := scenarioFollowUps[name]
			if !ok {
				return
			}
			vars[followUp.variable] = followUp.read(t, app, run)
			runHurl(t, app, filepath.Join(filepath.Dir(file), followUp.file), vars)
		})
	}
}

func startScenarioApp(t *testing.T, root, adminTokenHash string) testcontainers.Container {
	t.Helper()
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

	app, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    root,
				Dockerfile: "Dockerfile",
				KeepImage:  true,
			},
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"MINIAUTH_DATABASE_URL":       "postgres://miniauth:miniauth@postgres:5432/miniauth?sslmode=disable",
				"MINIAUTH_ADMIN_TOKEN_SHA256": adminTokenHash,
				"MINIAUTH_PUBLIC_URL":         scenarioOrigin,
				"MINIAUTH_MAIL":               "log",
			},
			Networks: []string{nw.Name},
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
	return app
}

func runHurl(t *testing.T, app testcontainers.Container, file string, vars map[string]string) {
	t.Helper()
	ctx := t.Context()
	inside := "/scenarios/" + filepath.Base(file)
	args := []string{"--test"}
	for _, key := range slices.Sorted(maps.Keys(vars)) {
		args = append(args, "--variable", key+"="+vars[key])
	}
	args = append(args, inside)

	hurl, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: hurlImage,
			Cmd:   args,
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      file,
				ContainerFilePath: inside,
				FileMode:          0o444,
			}},
			HostConfigModifier: func(hc *container.HostConfig) {
				hc.NetworkMode = container.NetworkMode("container:" + app.GetContainerID())
			},
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
		text := containerLog(t, hurl)
		for _, secret := range []string{vars["admin_token"], vars["reset_token"]} {
			if secret != "" {
				text = strings.ReplaceAll(text, secret, "redacted")
			}
		}
		t.Log(text)
	}
	require.Equal(t, 0, state.ExitCode, "hurl %s", filepath.Base(file))
}

var resetLinkToken = regexp.MustCompile(`/recover/([A-Za-z0-9_-]+)`)

// resetTokenFromLog waits for the reset mail to <run>@example.test, the login of recovery.hurl.
// The mail goes out from a background queue, so it can reach the log after hurl exits.
func resetTokenFromLog(t *testing.T, app testcontainers.Container, run string) string {
	t.Helper()
	to := fmt.Sprintf("To: %s@example.test\n", run)
	var token string
	require.Eventually(t, func() bool {
		text := containerLog(t, app)
		_, mail, found := strings.Cut(text, to)
		if !found {
			return false
		}
		mail, _, _ = strings.Cut(mail, "miniauth: mail not sent")
		match := resetLinkToken.FindStringSubmatch(mail)
		if match == nil {
			return false
		}
		token = match[1]
		return true
	}, 30*time.Second, 200*time.Millisecond, "no reset mail for %s", to)
	return token
}

func containerLog(t *testing.T, c testcontainers.Container) string {
	t.Helper()
	logs, err := c.Logs(t.Context())
	require.NoError(t, err)
	defer func() { _ = logs.Close() }()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(logs)
	require.NoError(t, err)
	return buf.String()
}

func randomRunID() string {
	return strings.ToLower(rand.Text()[:runIDLength])
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
