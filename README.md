# miniauth

A small identity server in Go and PostgreSQL: password login, persistent browser sessions, personal access tokens, and a forward-auth endpoint for a reverse proxy such as Traefik.

Status: early. The service answers `GET /healthz`, `GET /readyz`, `GET /auth/check`, `GET /login`, `POST /login`, `GET /`, `POST /api/v1/users`, `POST /logout`, and `POST /logout/everywhere`.

`GET /healthz` reports that the process is up. `GET /readyz` returns 200 only when the process is ready to serve. It returns 503 when PostgreSQL does not answer, and while the process is shutting down. The process pings PostgreSQL every 5 seconds. A SIGTERM moves the process to draining and then shuts the HTTP server down.

Configuration comes from the `MINIAUTH_*` environment. The process checks it before it serves. `MINIAUTH_LISTEN` is the HTTP address. The default is `127.0.0.1:8080`. `MINIAUTH_DATABASE_URL` is the PostgreSQL connection string.

`GET /auth/check` is the Traefik `forwardAuth` target. A valid session answers 200 and sets `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`, and `X-Auth-Method`. `X-Auth-Email` is the login when the login contains `@`. `?group=` requires that group. A browser with no session is redirected to `{MINIAUTH_PUBLIC_URL}/login?return=`. Any other request with no session is 401 with `WWW-Authenticate: Bearer`. `?scope=` does not limit a session.

A personal access token is `idp_` and 43 base62 characters. A client sends it as `Authorization: Bearer idp_...`. The table `access_tokens` stores its SHA-256 and its first 8 characters, never the token. On `GET /auth/check` a valid token answers 200 with the same `X-Auth-*` headers as a session and `X-Auth-Method: token`. `?group=` still applies. A malformed, unknown, revoked, or expired token, or a token of a disabled user, is 401 with `WWW-Authenticate: Bearer error="invalid_token"`. A scope is a URL prefix: scheme, host, and path. The URL from `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` MUST be under one scope of the token, on a path segment border: `/mcp` covers `/mcp` and `/mcp/x`, not `/mcpx`. A URL under no scope is 403. A token with no scope reaches every URL of its user. `last_used_at` moves at most once a minute.

`MINIAUTH_PUBLIC_URL` is the origin of the login page, for example `https://id.example.test`. `MINIAUTH_COOKIE_DOMAIN` is the parent domain of the session cookie `__Secure-id_session`. An empty value is a host-only cookie. The return URL is kept only when its host is under that domain. With an empty domain, the host must match `MINIAUTH_PUBLIC_URL`. The cookie is HttpOnly, Secure, and SameSite=Lax. It lasts 30 days. The database stores the SHA-256 of the cookie, not the cookie.

`GET /login?return=<url>` starts a login flow and shows the login form. The flow id and secret go to the cookie `__Host-id_login_flow`, never to a URL. The cookie is HttpOnly, Secure, and SameSite=Lax, and it lasts 15 minutes. `POST /login` checks the login and the password. The `Origin` header MUST equal `MINIAUTH_PUBLIC_URL`. A missing or other `Origin` is 403. A correct password sets the session cookie and redirects with 303 to the return URL. A wrong login or password shows the form again with one message, and no session starts. After 5 failed tries in 15 minutes for one login or one client IP, each next try waits longer, up to one minute, and the reply is 429. A flow that completed cannot be used again. The return URL MUST be an https URL whose host is under `MINIAUTH_COOKIE_DOMAIN`, or equal to the host of `MINIAUTH_PUBLIC_URL` when the domain is empty. Any other return URL opens `GET /`, which shows the signed-in login.

The client IP of a login try is the TCP peer address. No trusted proxy is configured, so `X-Forwarded-For` is not read. Behind a reverse proxy, all tries share the address of the proxy for the IP backoff.

`docker compose up --build` starts PostgreSQL, miniauth, and a local Traefik. Traefik listens on `127.0.0.1:8088`. `/app` requires a session. `/editors` also requires the group `editors`. The cookie is `Secure`, so a browser on plain HTTP does not keep it. `curl` can send it.

`POST /api/v1/users` creates a user and one password identity. The body is JSON: `login` and `password`. The caller sends `Authorization: Bearer <token>`. `MINIAUTH_ADMIN_TOKEN_SHA256` is the hex SHA-256 of that token. The token is not in the config. `GET /openapi.yaml` serves the description generated from the handlers. When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, request and database spans are exported there. A query string, a header, and a SQL argument are not span attributes.

## Release

A published GitHub release with a tag such as `v0.1.0` builds the image from `Dockerfile` and pushes it to `ghcr.io/popoffvg/miniauth` with the tags `0.1.0`, `0.1`, and `latest`.

## Development

```sh
mise install   # Go 1.27 and task
task setup     # build the pinned tools, install the pre-push hook
task check     # lint, vet, gosec, tests with coverage
```

CI runs golangci-lint, go vet, gosec (results in the Security tab), and the tests with a gocov report. CodeRabbit reviews each pull request with the rules in `.coderabbit.yaml`.

### Amp orbs

`.agents/setup` installs the toolchain from `mise.toml`, downloads both Go modules,
builds the pinned tools and the service, and prepares PostgreSQL 17. Amp can reuse
these files and caches in project snapshots. `.agents/resume` restores the pre-push
hook without installing dependencies.

Start the local test database with `amp orb services ensure`. Then run `task check`.
New login shells in this checkout load the toolchain and set
`MINIAUTH_TEST_DATABASE_URL` unless it is already set. The database listens on
loopback only. It uses trust authentication and has durability disabled. It MUST
NOT hold real data. No secrets are required for these tests.

The Docker-based Hurl test needs a Docker daemon. This orb setup does not install
or start Docker. Without its socket, that test is skipped. The PostgreSQL
integration tests use the supervised database and do not need Docker or
`task test:integration`.
