# miniauth

A small identity server in Go and PostgreSQL: password login, persistent browser sessions, personal access tokens, and a forward-auth endpoint for a reverse proxy such as Traefik.

Status: early. The service answers `GET /healthz` and `POST /api/v1/users`.

`POST /api/v1/users` creates a user and one password identity. The body is JSON: `login` and `password`. The caller sends `Authorization: Bearer <token>`. `MINIAUTH_ADMIN_TOKEN_SHA256` is the hex SHA-256 of that token. The token is not in the config. The route is described in `api/openapi.yaml`.

## Development

```sh
mise install   # Go 1.27 and task
task setup     # build the pinned tools, install the pre-push hook
task check     # lint, vet, gosec, tests with coverage
```

CI runs golangci-lint, go vet, gosec (results in the Security tab), and the tests with a gocov report. CodeRabbit reviews each pull request with the rules in `.coderabbit.yaml`.
