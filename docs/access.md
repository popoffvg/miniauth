# Access

This page tells how miniauth decides that a request may open a URL.

## Resources and grants

A resource is a name, a host, and a path prefix, for example `dashboards` with `dash.example.test/mcp`. You give it as an absolute `http` or `https` URL with no query. miniauth stores only the host and the path.

A grant gives one resource to one user or to one group. A grant can have an expiry. An expired grant does not count.

Make resources and grants in the access page `GET /access`, the groups page `GET /groups`, the [access API](api.md#access), or the [resources file](#predefined-resources). A new install has no resources and no grants, so every URL is refused until you add them.

## The match rule

For a request URL, miniauth finds the resource on the same host with the longest path prefix. A prefix ends on a path segment border: `/mcp` covers `/mcp` and `/mcp/x`, not `/mcpx`.

The request may pass when that resource has an active grant for the user or for one of the user's groups. Each check reads the grants again, so a revoke applies to the next request.

## Groups

A group has a name, a set of members, and a set of resources. The set of resources is the grants to the group. A user reaches a resource through a grant to the user or to one of the user's groups.

A group name has 1 to 64 lower-case characters. The first and last are a letter or a digit. The rest can also be `.`, `_`, or `-`. A group MUST exist before a membership or a grant names it: an unknown group is 404.

Two groups are built in. They always exist and cannot be deleted:

- `admins`: only its members open the admin pages `/users`, `/groups`, and `/access`. An admin cannot leave `admins` and cannot disable its own account.
- `users`: every new account joins it.

An upgrade renames the old group `admin` to `admins`, and puts every existing account in `users`.

Manage groups in the groups page `GET /groups` or with the [group API](api.md#groups). Deleting a group deletes its memberships and its grants. Add a member in the users page `/users` or with `PUT /api/v1/groups/{group}/members/{login}`.

## Predefined resources

`MINIAUTH_RESOURCES_FILE` names a JSON file of resources and their groups (see [configuration.md](configuration.md#resources-file)). The rows that the file owns are managed.

At each start, in one transaction, miniauth:

1. creates or updates each resource of the file, and creates each group that the file names and that does not exist;
2. gives each listed group the resource;
3. deletes the managed resources and the managed group grants that the file no longer names.

A resource or a group grant that you made by hand, with the same name or the same resource and group as an entry, becomes managed. miniauth never changes another row that is not managed. With no file, the start deletes every managed row.

You cannot delete a managed resource, revoke a managed grant, or delete a group that the file names: the API and the pages answer 409. The pages show managed rows with a "From config" badge. To change them, change the file and restart.

## Forward-auth

Traefik calls `GET /auth/check` before each protected request. It sends the request URL in `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri`.

| Case | Answer |
| --- | --- |
| Valid session or token, group and grant match | 200 with the `X-Auth-*` headers |
| No session, browser navigation | 302 to `{MINIAUTH_PUBLIC_URL}/login?return=<url>` |
| No session, any other client | 401 with `WWW-Authenticate: Bearer` |
| Bad, unknown, revoked, or expired token, or a token of a disabled user | 401 with `WWW-Authenticate: Bearer error="invalid_token"` |
| User not in the group of `?group=` | 403 |
| No resource for the URL, no active grant, or no forwarded headers | 403 |
| URL outside every scope of the token | 403 |

A browser navigation is a request with `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`, or `Accept: text/html`, and with no `Authorization` header. An XHR or a CORS fetch is not a navigation.

The 403 for a missing grant names the URL, without its query, and the login. A browser gets an HTML page. Another client gets `application/problem+json`.

`?group=` can repeat. The user MUST be in each named group. `?scope=` does not limit a session.

The 200 answer sets:

| Header | Value |
| --- | --- |
| `X-Auth-User` | The login. |
| `X-Auth-Email` | The login when it contains `@`, else empty. |
| `X-Auth-Groups` | The groups of the user, sorted and comma-separated. |
| `X-Auth-Method` | The factors of the session, such as `password,totp`, or `token` for a personal access token. |

## Personal access tokens

A personal access token is `idp_` and 43 base62 characters. A client sends it as `Authorization: Bearer idp_...`. On `/auth/check` a valid token gives the same headers as a session, with `X-Auth-Method: token`.

A user makes tokens in `GET /tokens`. The page shows a new token once. A token has a name, scopes, and an optional expiry date. It works until the end of that UTC day. Making a token needs a recent login (see [step-up](login-methods.md#step-up)). `POST /tokens/{id}/revoke` revokes a token.

An admin can also import a token from a secret store with `POST /api/v1/tokens/import`, so the client keeps its token.

### Scopes

A scope is a URL prefix: scheme, host, and path. The request URL MUST be under one scope of the token, on a path segment border. A token with no scope reaches every URL its user has a grant for. A scope never replaces a grant: the URL also needs a grant for the token user or one of the user's groups.

## Invites

There is no public sign-up. An account exists only through an invite or `POST /api/v1/users`.

An invite lets one new person make an account in one group. An admin makes it in `/users` or with `POST /api/v1/invites`. With no group, the invite is to `users`. The link is `{MINIAUTH_PUBLIC_URL}/invite/{token}`. It is shown once, works once, and expires after 7 days.

The person opens the link and chooses a login and a password. In one transaction miniauth marks the invite used and creates the user in the group of the invite and in `users`. Then it starts a session and redirects to the overview page `/`. A taken login shows the form again with 409, and the invite stays unused. An unknown, used, or expired link is 410. An invite is open, used, or expired. Only an open invite accepts: accept moves it to used, and its expiry moves it to expired. Two acceptances of one link at the same moment create one account. The other gets 410 with the message that another request used the link.

## Sessions and devices

Each browser gets a device cookie. A device has at most one session: a new login on a known device replaces its session. The security page `GET /sessions` lists the devices of the user, with a short name such as "Firefox on macOS".

- `POST /sessions/{device}/signout` deletes the session of that device and keeps the device.
- `POST /sessions/{device}/forget` deletes the device and its session.
- `POST /logout` deletes the session of the request.
- `POST /logout/everywhere` deletes every session of the user.

A disabled user loses every session at once, and the next `/auth/check` is refused.
