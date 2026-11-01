# API

`api/openapi.yaml` is the full reference: every route, body, and status. The server also serves it at `GET /openapi.yaml`. Both are generated from the route table in `internal/api/router.go`. This page is a short map.

## Admin API

Each admin route needs `Authorization: Bearer <admin token>`. `MINIAUTH_ADMIN_TOKEN_SHA256` holds the SHA-256 of that token. A missing or wrong token is 401. Each error is `application/problem+json`. A JSON body needs `Content-Type: application/json`.

### Users

| Route | What it does |
| --- | --- |
| `POST /api/v1/users` | Creates a user with a password. Body: `login`, `password`. 201; a taken login is 409. |
| `GET /api/v1/users` | Lists every user with the groups, the state, the device count, and the last time a device was seen. |
| `POST /api/v1/users/{login}/disable` | Disables the user and deletes every session of the user. 204. A change of the same user at the same moment is 409. |
| `POST /api/v1/users/{login}/enable` | Enables the user. The user signs in again. 204. A change of the same user at the same moment is 409. |

A login has 1 to 64 characters, stored in lower case. The first and last are a letter or a digit. The rest can also be `.`, `_`, `@`, `+`, or `-`. An unknown login is 404.

### Groups

| Route | What it does |
| --- | --- |
| `GET /api/v1/groups` | Lists every group in name order, with `built_in`, the member count, and the resources. |
| `POST /api/v1/groups` | Creates an empty group. Body: `name`. 201; a taken name is 409. |
| `DELETE /api/v1/groups/{group}` | Deletes the group, its memberships, and its grants. 204. A built-in group, or a group that `MINIAUTH_RESOURCES_FILE` names, is 409. |
| `PUT /api/v1/groups/{group}/members/{login}` | Adds the user to the group. Idempotent. 204; an unknown user or group is 404. |
| `DELETE /api/v1/groups/{group}/members/{login}` | Removes the user from the group. 204; a user not in the group is 404. |
| `PUT /api/v1/groups/{group}/resources/{name}` | Gives the group the resource, with no expiry. Idempotent. 204; an unknown group or resource is 404. |
| `DELETE /api/v1/groups/{group}/resources/{name}` | Revokes the grant of the resource to the group. 204; a group without the resource is 404; a managed grant is 409. |

### Access

| Route | What it does |
| --- | --- |
| `POST /api/v1/resources` | Creates a resource. Body: `name`, `url`. 201; a taken name, or a taken host and path, is 409. |
| `GET /api/v1/resources` | Lists the resources in name order. |
| `DELETE /api/v1/resources/{name}` | Deletes the resource and its grants. 204 or 404; a managed resource is 409. |
| `POST /api/v1/grants` | Grants a resource. Body: `resource`, exactly one of `user` and `group`, optional `expires_at` (RFC 3339, in the future). 201 with the grant `id`. |
| `GET /api/v1/grants?user=<login>&resource=<name>` | Lists grants, expired ones too. Both filters are optional. `user` selects grants to that user, not to the user's groups. |
| `DELETE /api/v1/grants/{id}` | Revokes the grant. 204; a managed grant is 409. |

### Tokens and invites

| Route | What it does |
| --- | --- |
| `POST /api/v1/tokens/import` | Stores a token made outside miniauth. Body: `user`, `name`, `scopes` (at least one), `token` (`idp_...`). 201 the first time; 200 when the user already has it; 409 when another user has it. The token does not expire. The reply never has the token. |
| `POST /api/v1/invites` | Makes an invite link to one group. Body: optional `group`, default `users`. 201 with `link`, `group`, and `expires_at`; an unknown group is 404. 503 without `MINIAUTH_PUBLIC_URL`. |

## Health

| Route | What it does |
| --- | --- |
| `GET /healthz` | The process is up. |
| `GET /readyz` | 200 when the process is ready. 503 when PostgreSQL does not answer, and while the process shuts down. |

A SIGTERM moves the process to draining: `/readyz` answers 503 while open requests finish. Then the HTTP server stops.

## Forward-auth

`GET /auth/check` is the Traefik target. See [access.md](access.md#forward-auth).

## Browser routes

These routes serve HTML pages and forms. Each POST needs an `Origin` equal to `MINIAUTH_PUBLIC_URL`, else 403.

| Area | Routes |
| --- | --- |
| Login | `GET/POST /login`, `POST /login/google`, `GET /login/google/callback`, `GET /login/telegram/callback`, `POST /login/passkey/options`, `POST /login/passkey`, `GET/POST /login/totp`, `GET/POST /login/recovery-code` |
| Account linking | `GET/POST /link` |
| Recovery | `GET/POST /recover`, `GET /recover/{token}`, `POST /recover/reset` |
| Invites | `GET /invite/{token}`, `POST /invite/accept` |
| Overview | `GET /` |
| Tokens | `GET/POST /tokens`, `POST /tokens/{id}/revoke` |
| Security | `GET /sessions`, `POST /sessions/{device}/signout`, `POST /sessions/{device}/forget`, `POST /sessions/totp/enroll`, `POST /sessions/totp/confirm`, `POST /sessions/totp/disable` |
| Passkeys | `GET /passkeys/new`, `POST /passkeys/options`, `POST /passkeys`, `POST /passkeys/{id}/delete` |
| Admin pages | `GET /users`, `GET /groups`, `GET /access`, and their forms: `POST /groups`, and POST routes under `/users/`, `/groups/`, and `/access/` |
| Sign out | `POST /logout`, `POST /logout/everywhere` |
| Assets | `GET /assets/app.css`, `GET /assets/passkey.js` |

After a change, a page POST redirects with `?done=<result>`, and the page shows a fixed message for that result.
