# MCP server for agents

miniauth serves an MCP server at `POST /mcp`. An agent uses it to make a short-lived personal access token, and then calls a protected endpoint with that token as the signed-in user.

## Sign-in

The endpoint is a resource of miniauth itself, and the agent signs in with the [OAuth flow](oauth.md):

1. An admin stores the resource `https://<miniauth host>/mcp` and gives a group a grant on it (`POST /api/v1/resources`, `PUT /api/v1/groups/{group}/resources/{name}`).
2. An admin registers the agent as a client (`POST /api/v1/oauth/clients`).
3. The agent calls `/mcp` with no token, gets 401 with `resource_metadata`, and runs the OAuth flow. The user allows the agent once on the consent page.

The reverse proxy MUST send `/mcp` and `/.well-known/oauth-protected-resource/mcp` on the miniauth host to miniauth with no forward-auth.

A personal access token with a scope that covers `https://<miniauth host>/mcp` also works. The user needs the grant in both cases.

## Tools

| Tool | Input | Output |
| --- | --- | --- |
| `list_resources` | none | The URL prefixes that the user has a grant on. Each one is a valid scope. |
| `mint_token` | `scopes`: 1 to 16 URL prefixes. `name` (optional): shown on the Tokens page as `mcp: <name>`. | `token`, `expires_at`, `scopes`. The token works for 10 minutes. |

A scope is a URL prefix, matched against the URL that the reverse proxy forwards (`X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri`). `mint_token` refuses a scope:

- that is not an http or https URL with no query,
- that is on the miniauth host, so a minted token cannot mint again,
- that is not under a resource the user has a grant on. A scope wider than its resource is refused too.

The minted token is in the tool reply only. It is listed on the Tokens page, and the user can revoke it there.

## Example

```text
tools/call list_resources → {"resources":[{"name":"vocabulary","url":"https://app.example.test/"}]}
tools/call mint_token {"scopes":["https://app.example.test/v1/"],"name":"smoke"} → {"token":"idp_…","expires_at":"…"}
curl -H "Authorization: Bearer idp_…" https://app.example.test/v1/me
```
