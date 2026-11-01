# miniauth

A small identity server in Go. It signs users in, keeps browser sessions, issues personal access tokens, and answers the reverse proxy's forward-auth check. State lives in PostgreSQL.

The design documents live in the owner's private infrastructure repo, not here. Ask the owner for them before you change a flow, a table, or an endpoint.

## What the service does

- Password login, with a browser session that persists across restarts and subdomains.
- Personal access tokens: the user makes a token once, and a client sends it as `Authorization: Bearer <token>`.
- One forward-auth endpoint that the reverse proxy calls before each protected request.
- More login methods: TOTP, passkey, Google, Telegram. Each method is a step of the login flow. A new method does not change sessions or tokens.

## Rules

- Write in simple English (ASD-STE100). Short sentences. RFC 2119 keywords for obligations.
- A secret MUST NOT reach a log, an error message, a URL, or a database column in clear text. Store a hash of each session id and each token.
- Compare secrets in constant time (`crypto/subtle`).
- Domain-driven design: each entity, value object, id, and DTO has its own named type. A bare `string`, `[]byte`, or `uuid.UUID` MUST NOT carry a domain concept in a signature or a field. A DTO stays in its adapter package.
- Each schema change is a new numbered migration in `migrations/`. Never edit a migration that is on `main`.
- SQL lives in `queries/*.sql` and goes through `sqlc`. No SQL strings in Go code.
- Use the standard library first: `net/http` routing, `log/slog`. Add a dependency only when the standard library has no equal.
- HTML pages are templ components in `internal/api/*.templ`. Run `task templ` after each change and commit the generated `_templ.go` files. Every page uses the one stylesheet `internal/api/assets/app.css`: no inline style, no other CSS.
- A comment states an invariant or an outside assumption. It MUST NOT say what the code says. No ticket ids or links in code.
- Nothing in this repo names a real host, server, or deployment. This repo is public.
- Commit subject in imperative mood. No co-author lines.

## Documentation

- `README.md` is for people who run the service: what it is, quickstart, deploy, main settings, links.
- Reference and developer text goes in `docs/`, one concept per file. A fact lives in one file only.
- A change that adds a route, a setting, or a login method MUST update the matching docs file in the same PR.

## Commands

Go and task are pinned in `mise.toml`; the linters, gosec, and gocov are pinned as `go tool` entries in `tools/go.mod`. Run every task in the background.

| Task | Command |
| --- | --- |
| First setup: tools and the pre-push hook | `mise install && task setup` |
| Lint (golangci-lint with govet and gosec) | `task lint` |
| Format | `task fmt` |
| Generate the pages from `*.templ` | `task templ` |
| Generate Go from `queries/*.sql` (sqlc) | `task generate` |
| Tests with the race detector | `task test` |
| Tests against the local PostgreSQL | `task test:integration` |
| Coverage report (gocov) | `task cover` |
| Everything CI runs | `task check` |
| Per-rule review of the branch against `.reviewrules/` | `task review:rules` |

The pre-push hook runs `task lint` and `task test`. Fix the failure; never push with `--no-verify`.

The test kinds and the release flow are in `docs/development.md`.
