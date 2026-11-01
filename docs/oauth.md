# OAuth for MCP clients

miniauth is the authorization server. A resource of the access API is the protected MCP server.

An admin registers each client with `POST /api/v1/oauth/clients`. The body has `name` and `redirect_uris`. The client gets a `client_id` and no secret. A redirect URI MUST be https, or http on a loopback host. A loopback URI matches on any port.

A 401 from `/auth/check` for a URL under a resource names `resource_metadata` in `WWW-Authenticate`. The reverse proxy MUST send `/.well-known/oauth-protected-resource*` on each MCP host to miniauth, with no forward-auth.

`GET /oauth/authorize` requires PKCE S256 and a `resource` parameter that matches the URL of a stored resource. With no session, the browser goes to the login page first. The user allows the client once per resource on the consent page.

`POST /oauth/token` gives an `idp_` access token that reaches only that resource for one hour, and an `idr_` refresh token. Each refresh gives a new refresh token. A code or a refresh token sent a second time ends the consent and every token of it. A `resource` parameter that is not the consent is `invalid_target`.

`/auth/check` reads the access token as a personal access token, so a grant on the resource is still required. The token page lists the connected apps. Disconnect ends their tokens at once. The database keeps only the SHA-256 of each code and each token.
