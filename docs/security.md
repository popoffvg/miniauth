# Security

## Cookies

| Cookie | Holds | Domain | Lifetime |
| --- | --- | --- | --- |
| `__Secure-id_session` | The session id. | `MINIAUTH_COOKIE_DOMAIN`, or host-only when empty | 30 days after the last use. A use moves the expiry at most once an hour and sets the cookie again. |
| `__Secure-id_device` | The device id of this browser. It stays after logout. | Same as the session cookie | 2 years |
| `__Host-id_login_flow` | The id and secret of an open login flow. | Host-only | 15 minutes |
| `__Host-id_google_verifier` | The PKCE verifier of a Google login. | Host-only | 15 minutes |
| `__Host-id_pending_link` | The secret of a pending Google or Telegram link. | Host-only | 15 minutes |

Every cookie is HttpOnly, Secure, and SameSite=Lax, with `Path=/`. A browser that does not keep a Secure cookie on plain HTTP cannot sign in over HTTP.

## What is hashed

The database never stores a secret in clear text.

| Secret | Stored as |
| --- | --- |
| Password | argon2id hash |
| Session id, device id | SHA-256 |
| Personal access token | SHA-256 and the first 8 characters |
| Recovery code (two-step login) | SHA-256. A code has 80 random bits, so a slow hash adds nothing. |
| Password reset link, invite link | SHA-256 of the token |
| Login flow secret | Salted hash |
| Google PKCE verifier, state, nonce | SHA-256, so a copy of the database cannot finish a login |
| Telegram login data | SHA-256 of the id, `auth_date`, and hash, to refuse a replay |
| TOTP secret | Encrypted with AES-GCM under `MINIAUTH_TOTP_KEY` |
| Admin token | Only its SHA-256 is in the config |

Each comparison of a secret is constant time.

## Content-Security-Policy

Every page has `default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'`. A page has no inline style and no inline script. It loads one stylesheet, `/assets/app.css`. Each page also sends `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.

Two pages open more:

- The login page and `/passkeys/new` load `/assets/passkey.js` with `script-src 'self'` and `connect-src 'self'`.
- When Telegram is on, the login page allows `script-src https://telegram.org` and `frame-src https://oauth.telegram.org`.

`form-action` is not set: a browser applies it to the redirect after a form, and the return URL can be on another subdomain.

Pages that show a secret once (a new token, a TOTP secret, recovery codes, an invite link) send `Cache-Control: no-store`. The reset and invite forms send `Referrer-Policy: no-referrer`.

## Origin checks

Each browser POST MUST send an `Origin` header equal to the origin of `MINIAUTH_PUBLIC_URL`. A missing or other `Origin` is 403. This is the defence against cross-site form posts.

The Telegram callback is a GET from another site, so it has no `Origin` check. Its URL carries `flow_nonce`, an HMAC of the login flow secret. The callback refuses a nonce that is not the nonce of the flow in the cookie.

## Logs and traces

The process writes JSON logs to standard output, one line per request.

- A request line has the method, the path, the status, the time, and the request id. It has no headers, no query, and no body.
- A path that holds a secret, such as `/recover/{token}` or `/invite/{token}`, is logged as its route pattern.
- An `X-Request-ID` that contains a credential of the request, or `idp_`, is replaced with a new id.
- Spans have no query, no header, and no SQL argument.
- The config log shows `redacted` for the database URL and the admin token hash.
- A config error names the variable, never its value.

## Secrets in the config

These variables hold secrets: `MINIAUTH_DATABASE_URL` (it can hold a password), `MINIAUTH_SMTP_PASSWORD`, `MINIAUTH_GOOGLE_CLIENT_SECRET`, `MINIAUTH_TELEGRAM_BOT_TOKEN`, and `MINIAUTH_TOTP_KEY`. Keep them in a secret store. `MINIAUTH_ADMIN_TOKEN_SHA256` is a hash; keep the admin token itself in a secret store.

`MINIAUTH_MAIL=log` writes live reset links to the log. Use it only for local work.

## Known limits

These are known and accepted. Each has a low impact or is the design.

- The TOTP key URI holds the TOTP secret. The setup page shows it once as a QR code: that is how an authenticator app gets the secret.
- `MINIAUTH_MAIL=log` writes live reset links to the log. It is for local work only, never for real users.
- The passkey challenge is in the page and in the request. It is a public nonce, not a secret.
- Forward-auth tells a browser from another client by `Sec-Fetch-*` and `Accept`. A client that sends other headers gets 401 instead of a redirect to the login page.
- A double click on the passkey button can start two ceremonies. One of them fails, and the user tries again.
- Concurrent wrong passwords can all pass the backoff check before the first failure is stored, so a burst gets a few more tries than the limit.
- A recovery code is spent even when a later step of the same login fails.
- A session can expire between the check and its use in the same request, and a logout can race with an extension of the same session.
- Two failed tries with the same timestamp count as one for the backoff.
- A token that expires within one microsecond of a check can pass that check.
