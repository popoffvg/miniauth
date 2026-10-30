# miniauth

A small identity server in Go and PostgreSQL: password login, persistent browser sessions, personal access tokens, and a forward-auth endpoint for a reverse proxy such as Traefik.

Status: early. The service answers `GET /healthz`, `GET /auth/check`, `POST /api/v1/users`, `POST /logout`, and `POST /logout/everywhere`.

`GET /auth/check` is the Traefik `forwardAuth` target. A valid session answers 200 and sets `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`, and `X-Auth-Method`. `X-Auth-Email` is the login when the login contains `@`. `?group=` requires that group. A browser with no session is redirected to `{MINIAUTH_PUBLIC_URL}/login?return=`. Any other request with no session is 401 with `WWW-Authenticate: Bearer`. `?scope=` does not limit a session.

`MINIAUTH_PUBLIC_URL` is the origin of the login page, for example `https://id.example.test`. `MINIAUTH_COOKIE_DOMAIN` is the parent domain of the session cookie `__Secure-id_session`. An empty value is a host-only cookie. The return URL is kept only when its host is under that domain. With an empty domain, the host must match `MINIAUTH_PUBLIC_URL`. The cookie is HttpOnly, Secure, and SameSite=Lax. It lasts 30 days. The database stores the SHA-256 of the cookie, not the cookie.

`docker compose up --build` starts PostgreSQL, miniauth, and a local Traefik. Traefik listens on `127.0.0.1:8088`. `/app` requires a session. `/editors` also requires the group `editors`. The cookie is `Secure`, so a browser on plain HTTP does not keep it. `curl` can send it.

`POST /api/v1/users` creates a user and one password identity. The body is JSON: `login` and `password`. The caller sends `Authorization: Bearer <token>`. `MINIAUTH_ADMIN_TOKEN_SHA256` is the hex SHA-256 of that token. The token is not in the config. `GET /openapi.yaml` serves the description generated from the handlers. When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, request and database spans are exported there. A query string, a header, and a SQL argument are not span attributes.

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
