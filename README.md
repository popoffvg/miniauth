# miniauth

miniauth is a small identity server for your own sites. It signs people in, keeps their browser sessions, and tells a reverse proxy such as Traefik who may open which URL. It is one Go binary, and it keeps its state in PostgreSQL.

## Features

- Password login, with an optional second step: a TOTP code or a recovery code.
- Passkeys (WebAuthn) that sign in alone.
- Sign-in with Google and with Telegram, linked to an existing account.
- A browser session per device. A user can see each device and sign it out.
- Personal access tokens for scripts and API clients.
- A forward-auth endpoint for Traefik.
- URL grants: a user or a group gets access to a host and a path prefix.
- Groups: each group has members and a set of resources. Every account is in the group `users`.
- Predefined resources and group grants from a JSON file, applied at each start.
- Invite links: a new person makes an account in one group.
- An admin panel for users, groups, resources, and grants.
- Password recovery by mail.

## Quickstart

You need Docker. The local stack runs PostgreSQL, miniauth, a test page, and Traefik on `http://127.0.0.1:8088`.

```sh
docker compose up --build
```

The local stack uses the admin token `dev-admin-token`. `compose.yaml` holds its SHA-256 in `MINIAUTH_ADMIN_TOKEN_SHA256`. For a real deploy, make your own token and its hash, and keep the token in your secret store:

```sh
token=$(openssl rand -base64 32)
printf '%s' "$token" | sha256sum   # MINIAUTH_ADMIN_TOKEN_SHA256
```

Create the first user:

```sh
curl -X POST http://127.0.0.1:8088/api/v1/users \
  -H 'Authorization: Bearer dev-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{"login": "alice@example.test", "password": "change-me-now"}'
```

Make the user an admin. The admin panel opens only for a member of the built-in group `admins`. Every account is already in the built-in group `users`:

```sh
curl -X PUT http://127.0.0.1:8088/api/v1/groups/admins/members/alice@example.test \
  -H 'Authorization: Bearer dev-admin-token'
```

Then:

1. Open `http://127.0.0.1:8088/login` and sign in.
2. Open `http://127.0.0.1:8088/users` for users and invites.
3. Open `http://127.0.0.1:8088/groups` for groups and their resources.
4. Open `http://127.0.0.1:8088/access` for resources and grants.

The cookies of miniauth have the Secure flag. If your browser does not keep them on plain HTTP, put miniauth behind HTTPS as shown below.

## Put it behind Traefik

Serve miniauth on its own host, for example `https://id.example.test`. Set `MINIAUTH_PUBLIC_URL` to that origin, and `MINIAUTH_COOKIE_DOMAIN` to the parent domain of your sites.

Add a `forwardAuth` middleware. The first middleware removes any `X-Auth-*` header that the client sends, so only miniauth sets them:

```yaml
http:
  middlewares:
    strip-auth:
      headers:
        customRequestHeaders:
          X-Auth-User: ""
          X-Auth-Email: ""
          X-Auth-Groups: ""
          X-Auth-Method: ""
    miniauth:
      forwardAuth:
        address: http://miniauth:8080/auth/check
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email
          - X-Auth-Groups
          - X-Auth-Method
        addAuthCookiesToResponse:
          - __Secure-id_session
  routers:
    dashboard:
      rule: Host(`dash.example.test`)
      middlewares: [strip-auth, miniauth]
      service: dashboard
```

To require a group too, use `address: http://miniauth:8080/auth/check?group=editors`. `addAuthCookiesToResponse` passes the session cookie that `/auth/check` sets again when it extends the session, so an active user stays signed in.

Each protected URL needs a resource and a grant. Without them, `/auth/check` answers 403. Make them in the admin panel at `/access` and `/groups`, with the API, or in the file of `MINIAUTH_RESOURCES_FILE`. With the API:

```sh
curl -X POST https://id.example.test/api/v1/resources \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"name": "dashboard", "url": "https://dash.example.test/"}'

curl -X POST https://id.example.test/api/v1/grants \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"resource": "dashboard", "group": "users"}'
```

The protected service reads the user from `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups`, and `X-Auth-Method`. The values and every answer of `/auth/check` are in [docs/access.md](docs/access.md#forward-auth).

## Main settings

miniauth reads its settings from the environment. It checks them before it serves, and it stops on a bad value.

| Variable | Default | What it does |
| --- | --- | --- |
| `MINIAUTH_DATABASE_URL` | required | The PostgreSQL connection string. |
| `MINIAUTH_ADMIN_TOKEN_SHA256` | required | The hex SHA-256 of the admin API token. |
| `MINIAUTH_PUBLIC_URL` | empty | The origin of miniauth, for example `https://id.example.test`. |
| `MINIAUTH_COOKIE_DOMAIN` | empty (host-only) | The parent domain of the session cookie, for example `example.test`. |
| `MINIAUTH_LISTEN` | `127.0.0.1:8080` | The HTTP address. The image sets `0.0.0.0:8080`. |
| `MINIAUTH_RESOURCES_FILE` | empty | A JSON file of predefined resources and group grants. |

All settings, with the resources file, mail, TOTP, Google, and Telegram: [docs/configuration.md](docs/configuration.md).

## Image and release

Each published GitHub release pushes `ghcr.io/<owner>/miniauth` with the tags `<version>`, `<major>.<minor>`, and `latest`. A prerelease gets only `<version>`.

## Documentation

- [Configuration](docs/configuration.md): every `MINIAUTH_*` variable.
- [Login methods](docs/login-methods.md): password, two-step login, passkeys, Google, Telegram, account linking.
- [Access](docs/access.md): resources, grants, groups, predefined resources, invites, forward-auth, personal access tokens.
- [API](docs/api.md): the admin API and the other routes.
- [Security](docs/security.md): cookies, hashes, CSP, Origin checks, logs.
- [Development](docs/development.md): setup, tests, release, project layout.
