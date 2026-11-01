# Configuration

miniauth reads every setting from the environment when it starts. It checks all of them before it serves. A bad value stops the process with an error that names the variable. The error never contains the value. The process takes no command-line arguments.

## Core

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_DATABASE_URL` | yes | none | The PostgreSQL connection string. It MUST parse as a pgx connection string. The process applies the migrations at start. |
| `MINIAUTH_ADMIN_TOKEN_SHA256` | yes | none | The SHA-256 of the admin API token, as 64 hex characters. The token itself is not in the config. |
| `MINIAUTH_LISTEN` | no | `127.0.0.1:8080` | The HTTP address, as `host:port`. The container image sets `0.0.0.0:8080`. |
| `MINIAUTH_PUBLIC_URL` | no | empty | The origin of miniauth, such as `https://id.example.test`. It MUST be an `http` or `https` URL with a host, and with no path, query, fragment, or user. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | no | empty | When set, request and database spans go to this OTLP endpoint. |

Make the admin token hash:

```sh
token=$(openssl rand -base64 32)
printf '%s' "$token" | sha256sum
```

`MINIAUTH_PUBLIC_URL` is needed for most browser features:

- Each browser POST MUST send an `Origin` equal to this origin.
- An unauthenticated browser is redirected to `{MINIAUTH_PUBLIC_URL}/login`.
- Google, Telegram, invites, recovery links, and passkeys build their URLs from it.

## Cookies

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_COOKIE_DOMAIN` | no | empty | The `Domain` of the session cookie and the device cookie, such as `example.test` or `.example.test`. Empty means a host-only cookie. |

The value MUST be a valid domain name with at least one letter. It also sets:

- the hosts a login can return to: a host under this domain, or the host of `MINIAUTH_PUBLIC_URL` when the domain is empty;
- the passkey relying party id: this domain without the leading dot, or the host of `MINIAUTH_PUBLIC_URL` when the domain is empty.

## Resources file

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_RESOURCES_FILE` | no | empty | The path of a JSON file of predefined resources and their group grants. |

```json
{"resources": [
  {"name": "dashboards", "url": "https://dash.example.test/", "groups": ["users"]}
]}
```

Rules:

- The document MUST be an object with a `resources` array. Each entry MUST have `name` and `url`. `groups` is optional. An unknown field is an error.
- A name or a URL MUST NOT repeat an earlier entry.
- The file MUST NOT be larger than 1 MiB.
- A bad file stops the start. The error names the variable and the index of the entry, such as `resources[2]`. It never quotes the file.

At each start, miniauth makes the managed rows equal to the file. See [access.md](access.md#predefined-resources). With the variable unset or empty, the start deletes every managed row.

## Mail

Mail is used for password recovery. Choose one of two modes, or none.

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_MAIL` | no | empty | `log` writes each mail, with its live link, to the process output. For local work only. MUST NOT be used with real users. Any other non-empty value is an error. |
| `MINIAUTH_SMTP_HOST` | no | empty | The SMTP relay. It turns on SMTP mail. |
| `MINIAUTH_SMTP_PORT` | no | `587` | The relay port, 1 to 65535. |
| `MINIAUTH_SMTP_FROM` | with the host | none | The bare sender address, such as `id@example.test`. No display name. |
| `MINIAUTH_SMTP_USER` | no | empty | The relay user. Set it together with the password, or neither. |
| `MINIAUTH_SMTP_PASSWORD` | no | empty | The relay password. |

Rules:

- `MINIAUTH_MAIL=log` and `MINIAUTH_SMTP_HOST` MUST NOT be set together.
- A `MINIAUTH_SMTP_*` value without `MINIAUTH_SMTP_HOST` is an error.
- The relay MUST offer STARTTLS with a certificate valid for the host. No mail goes out in clear text.
- With no mail mode, the recovery routes answer 503 and the login page hides the recovery link.

## TOTP

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_TOTP_KEY` | no | empty | 32 random bytes in standard base64. It encrypts each TOTP secret with AES-GCM. |

Make a key with `openssl rand -base64 32`. Without the key, a user cannot turn on two-step login, and a TOTP code is refused. A user who already has two-step login can then sign in only with a recovery code.

## Google

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_GOOGLE_CLIENT_ID` | no | empty | The OAuth client id. |
| `MINIAUTH_GOOGLE_CLIENT_SECRET` | no | empty | The OAuth client secret. |

Set both or neither. Both also need `MINIAUTH_PUBLIC_URL`. See [login-methods.md](login-methods.md#google) for the OAuth client.

## Telegram

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `MINIAUTH_TELEGRAM_BOT_NAME` | no | empty | The bot user name: 5 to 32 letters, digits, or underscores. |
| `MINIAUTH_TELEGRAM_BOT_TOKEN` | no | empty | The bot token. It is a secret. |

Set both or neither. Both also need `MINIAUTH_PUBLIC_URL`. See [login-methods.md](login-methods.md#telegram) for the bot.

## Fixed values

These are not settings. They are listed here so you do not look for them:

| Value | |
| --- | --- |
| Session lifetime | 30 days |
| Device cookie lifetime | 2 years |
| Login flow lifetime | 15 minutes |
| Step-up age | 10 minutes |
| Recovery link lifetime | 30 minutes |
| Invite link lifetime | 7 days |
| Database health check | every 5 seconds |
