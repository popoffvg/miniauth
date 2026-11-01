# Development

The rules for code and text are in [AGENTS.md](../AGENTS.md). This page tells how to build, test, and release.

## Setup

Go and task are pinned in `mise.toml`. The linters, gosec, sqlc, templ, and gocov are pinned as `go tool` entries in `tools/go.mod`.

```sh
mise install   # Go and task
task setup     # build the pinned tools, install the pre-push hook
```

The pre-push hook runs `task lint` and `task test`. Fix the failure; never push with `--no-verify`.

## Tasks

| Task | What it does |
| --- | --- |
| `task setup` | Builds the pinned tools and installs the pre-push hook. |
| `task lint` | golangci-lint, with govet and gosec. |
| `task fmt` | Formats with gofumpt and goimports. |
| `task vet` | `go vet`. |
| `task sec` | gosec with its own report. |
| `task generate` | Generates `internal/postgres/sqlcgen` from `queries/*.sql` with sqlc. |
| `task templ` | Generates the `_templ.go` files from `internal/views/*.templ`. |
| `task db:up` | Starts the local PostgreSQL from `compose.yaml` and waits until it is healthy. |
| `task test` | All tests with the race detector. |
| `task test:integration` | All tests against the local PostgreSQL. |
| `task cover` | Tests with a gocov report. HTML in `coverage/index.html`. |
| `task check` | Everything CI runs: lint, vet, sec, cover. |
| `task review:rules` | Per-rule LLM review of the branch. See [Rule review](#rule-review). |

## Tests

| Kind | Where | Needs |
| --- | --- | --- |
| Unit | `*_test.go` next to the code | Nothing. |
| PostgreSQL | `internal/postgres/*_test.go` and other tests that call `postgrestest.NewDatabase` | `MINIAUTH_TEST_DATABASE_URL`, a user that can create databases. Each test makes its own database and drops it. Without the variable the test is skipped, except in CI, where it fails. `task test:integration` sets it. |
| Go end-to-end | `internal/api/*_e2e_test.go` | PostgreSQL, as above. The tests run the full router over HTTP. |
| Hurl scenarios | `testdata/scenarios/*.hurl`, run by `TestScenarios` in `internal/api/e2e_test.go` | Docker. Without Docker the test is skipped. See [Integration scenarios](#integration-scenarios). |
| Compose Traefik | `TestTraefikProtectsThePage` in `internal/api/forwardauth_compose_test.go` | Docker and `MINIAUTH_COMPOSE=1`. It starts `compose.yaml`, adds the resources and grants, and checks each route through Traefik. |

Run the compose test:

```sh
MINIAUTH_COMPOSE=1 go test ./internal/api -run TestTraefikProtectsThePage
```

In the local stack, Traefik listens on `127.0.0.1:8088`. `/app` needs a session and a grant on the resource `127.0.0.1:8088/app`. `/editors` also needs the group `editors` and a grant on `127.0.0.1:8088/editors`. Every miniauth page is routed to miniauth.

## Integration scenarios

The black-box scenarios are Hurl files in `testdata/scenarios/`. `TestScenarios` in `internal/api/e2e_test.go` builds the image, starts it once with PostgreSQL, and runs each file as its own subtest. Each file gets a fresh run id, so its logins and resources are unique and the files run in any order.

The image runs with `MINIAUTH_MAIL=log`. Hurl cannot read the container log, so the runner reads the reset link of `recovery.hurl` from the log and passes its token to `recovery_reset.hurl`.

Run one scenario with `go test ./internal/api -run TestScenarios/<name>`, for example `TestScenarios/login_logout`. It needs a Docker daemon.

Some cases stay in the Go tests:

- Google, Telegram, passkey, and TOTP logins. They need a fake OIDC provider, a signed Telegram payload, a WebAuthn authenticator, or a fixed clock. Hurl has none of these.
- The expiry cases, which need the clock.
- The login backoff. Every scenario uses one client IP, so a backoff in one file would refuse the logins of the others.

## Rule review

`.reviewrules/config.json` holds the rules from AGENTS.md. `task review:rules` runs `reviewrules` (pinned in `tools/go.mod`) on the branch against `origin/main`, with the uncommitted change. Each rule gets its own LLM check, and a separate check looks for bugs that no rule names.

The backend comes from `~/.config/reviewrules/config.toml`, for example `[local]` with `agent = "codex"` after `codex login`. You MAY pass more flags after `--`, for example `task review:rules -- --json-out report.json`.

## Database

- Each schema change is a new numbered file in `migrations/`. Never edit a migration that is on `main`. The process applies the migrations at start.
- SQL lives in `queries/*.sql`. Run `task generate` after a change and commit `internal/postgres/sqlcgen`.
- CI fails when the sqlc output is not up to date.

## Pages

Each HTML page is a templ component in `internal/views/*.templ`. Run `task templ` after a change and commit the `_templ.go` files. CI fails when the templ output is not up to date. Every page uses the one stylesheet `internal/views/assets/app.css`.

## Routes

Each HTTP route is a row in `routes()` in `internal/api/router.go`. `api/openapi.yaml` is generated from those rows, and a test fails when the file is not current. Run `UPDATE_OPENAPI=1 go test ./internal/api -run OpenAPI` to write it again.

## CI

`.github/workflows/ci.yml` runs on each pull request and each push to `main`:

- sqlc and templ output checks, golangci-lint, and `go vet`;
- gosec, with the results in the GitHub Security tab;
- the tests against PostgreSQL 17, with a gocov report in the job summary.

## Release

`.github/workflows/release.yml` runs on a published GitHub release. It builds `Dockerfile` and pushes `ghcr.io/<owner>/miniauth`:

- a stable tag such as `v0.1.0` gets `0.1.0`, plus `0.1` when it is the newest of that series, plus `latest` when it is the newest release;
- a prerelease gets only its version.

An older release that is published later does not move `latest` or its `major.minor` tag.

## Amp orbs

`.agents/setup` installs the toolchain from `mise.toml`, downloads both Go modules, builds the pinned tools and the service, and prepares PostgreSQL 17. `.agents/resume` installs the pre-push hook again without other work.

Start the local test database with `amp orb services ensure`, then run `task check`. The database listens on loopback only, uses trust authentication, and has durability off. It MUST NOT hold real data. The orb does not start Docker, so the Hurl scenarios and the compose test are skipped there.

## Project layout

| Path | What it holds |
| --- | --- |
| `cmd/miniauth` | The binary: config, wiring, HTTP server, shutdown. |
| `internal/config` | The `MINIAUTH_*` settings and the resources file parser. |
| `internal/api` | HTTP routes, pages, forward-auth, admin API. Every DTO stays here. |
| `internal/loginflow` | The login flow engine: steps, factors, flow store. |
| `internal/providers/<name>` | One login method each: `password`, `totp`, `passkey`, `google`, `telegram`. |
| `internal/sessions`, `internal/devices` | Browser sessions and device cookies. |
| `internal/users`, `internal/groups` | Accounts and groups, with the built-in groups. |
| `internal/useradmin`, `internal/groupadmin` | The users and groups admin services. |
| `internal/access` | Resources, grants, the URL match rule, and the reconcile of the resources file. |
| `internal/tokens` | Personal access tokens and scopes. |
| `internal/invites`, `internal/recovery`, `internal/identitylink` | Invites, password recovery, pending account links. |
| `internal/mailer` | SMTP and log mail. |
| `internal/lifecycle` | Readiness and shutdown states. |
| `internal/telemetry` | OpenTelemetry setup. |
| `internal/postgres` | Repositories, migrations runner, `sqlcgen`, and `postgrestest`. |
| `migrations/`, `queries/` | Schema and SQL. |
| `api/openapi.yaml` | The generated API description. |
| `compose.yaml`, `compose/` | The local stack. |
| `testdata/scenarios/` | Hurl scenarios. |
| `.reviewrules/` | The rules and settings of `task review:rules`. |
