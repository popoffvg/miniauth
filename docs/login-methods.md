# Login methods

A login is a flow of steps. `GET /login?return=<url>` starts a flow and shows the login form. The flow lives 15 minutes. Its id and secret are in the cookie `__Host-id_login_flow`, never in a URL. A flow that completed cannot be used again.

A complete flow sets the session cookie and redirects with 303 to the return URL. The return URL MUST be an `https` URL whose host is under `MINIAUTH_COOKIE_DOMAIN`, or equal to the host of `MINIAUTH_PUBLIC_URL` when the domain is empty. Any other return URL opens `GET /`, the overview page.

The login methods give these factors. `X-Auth-Method` names the factors of the session in this order: `password`, `totp`, `recovery`, `passkey`, `google`, `telegram`.

## Password

`POST /login` checks the login and the password. A wrong login or password shows the form again with one message. No session starts.

Backoff: after 5 failed tries in 15 minutes for one login or one client IP, each next try waits longer. The wait starts at 1 second, doubles with each failure, and stops at 1 minute. A try during the wait answers 429. There is no hard lock.

The client IP is the TCP peer. miniauth does not read `X-Forwarded-For`, so behind a reverse proxy all tries share the proxy address for the IP backoff. An IPv6 client counts as its /64 network.

Passwords are stored as argon2id hashes. A password MUST NOT be empty and MUST NOT be longer than 1024 bytes.

## Two-step login (TOTP)

Two-step login adds a TOTP code after the first factor. The first factor is a password, Google, or Telegram. Two first factors do not count as two: password and Google still need the code. Every factor of one login MUST belong to the same user.

The code follows RFC 6238: SHA-1, 6 digits, 30 seconds, and one step of clock skew. The server needs `MINIAUTH_TOTP_KEY` (see [configuration.md](configuration.md#totp)).

Turn it on in the security page `GET /sessions`:

1. `POST /sessions/totp/enroll` makes a 20-byte secret and shows it once, as a QR code and as base32 text.
2. `POST /sessions/totp/confirm` turns two-step login on when the code from the app matches. It shows 10 recovery codes once. The setup expires after 15 minutes.
3. `POST /sessions/totp/disable` turns it off and deletes the recovery codes.

The setup has the stages none, pending, confirmed, and disabled:

| Stage | enroll | confirm | expire | disable |
| --- | --- | --- | --- | --- |
| none | pending | refused | refused | refused |
| pending | pending, with a new secret | confirmed | none | disabled |
| confirmed | refused | refused | refused | disabled |
| disabled | pending | refused | refused | refused |

A refused enroll shows the security page. A refused disable changes nothing and also returns to it. Two requests that change the setup at the same time, such as a confirm in one tab and a disable in another, cannot both succeed: the second one gets 409 and the message to try again.

At login, a user with two-step login sees the TOTP form after the first factor. `POST /login/totp` checks the code. Each code is accepted once.

## Recovery codes

A recovery code replaces a TOTP code once, at `GET /login/recovery-code` and `POST /login/recovery-code`. A used code is refused. Wrong TOTP codes and wrong recovery codes share one backoff per login, with the same rules as the password. A correct password does not reset it.

## Passkeys

A passkey is a WebAuthn discoverable credential with user verification. It counts as two factors, so it completes the login alone, with no TOTP code.

- The relying party id is `MINIAUTH_COOKIE_DOMAIN` without the leading dot, or the host of `MINIAUTH_PUBLIC_URL` when the domain is empty.
- The origin is the `MINIAUTH_PUBLIC_URL` origin.
- The id MUST be the public host or a parent of it, and MUST NOT be an IP address. Otherwise passkeys are off, the log has a warning, and the passkey routes answer 503.

A user adds a passkey at `GET /passkeys/new` and sees the passkeys in `GET /sessions`. A response without user verification, an unknown credential, or a signature counter that does not increase is refused with 400.

## Google

Google sign-in is on when `MINIAUTH_GOOGLE_CLIENT_ID` and `MINIAUTH_GOOGLE_CLIENT_SECRET` are set, with `MINIAUTH_PUBLIC_URL`.

Make the OAuth client:

1. In the Google Cloud console, create an OAuth client of the type "Web application".
2. Add the authorized redirect URI `{MINIAUTH_PUBLIC_URL}/login/google/callback`, for example `https://id.example.test/login/google/callback`.
3. Put the client id and the client secret in the two variables.

miniauth reads the Google discovery document at start and every 10 minutes. While discovery fails, the login page does not offer Google, and `POST /login/google` answers 503.

The login uses PKCE. The callback checks the state, the PKCE verifier, and the ID token: signature, issuer, audience, expiry, and nonce. Only the `sub` claim links a Google account to a user. miniauth does not read the email.

## Telegram

Telegram sign-in is on when `MINIAUTH_TELEGRAM_BOT_NAME` and `MINIAUTH_TELEGRAM_BOT_TOKEN` are set, with `MINIAUTH_PUBLIC_URL`.

Make the bot:

1. Create a bot with BotFather. Put its user name and token in the two variables.
2. Set the bot domain (`/setdomain` in BotFather) to the host of `MINIAUTH_PUBLIC_URL`.

The login page then shows the Telegram Login Widget in redirect mode. Telegram sends the browser to `GET /login/telegram/callback?flow_nonce=...`. The callback needs the login flow cookie of an open flow, and `flow_nonce` MUST belong to that flow. The nonce is an HMAC of the flow secret, so data that another browser received for its own flow is refused: an attacker cannot sign a victim in to the attacker's account. It checks the hash with the bot token. It refuses data that is one day old or more, data more than one minute in the future, and data that signed in before. Only the Telegram `id` links an account to a user.

## Account linking

Google and Telegram never create a user and never link an account by themselves.

1. A linked account signs in.
2. An unknown account starts no session. miniauth keeps it for 15 minutes as a pending link, bound to the browser by the cookie `__Host-id_pending_link`. The page asks for a password login.
3. After that password login, the browser goes to `GET /link`. The page names the account, for example "the Google account 1234", and asks to link it or not.
4. `POST /link` with `action=link` adds the account to the session user. `action=skip` deletes the pending link.

The confirm page exists because another site can put its own account in the pending link cookie. An expired pending link does not link. An account that is linked to another user is 409.

## Step-up

Some actions need a recent login: a login newer than 10 minutes. These are making a token, the two-step login routes, adding or deleting a passkey, and each change on `/users`, `/groups`, and `/access`. With an older login, the page asks for the password of the session user. A correct password renews the login time and returns to the page. The step-up checks the password only.

## Password recovery

Recovery works for a user whose login is an email address. It needs a mail mode (see [configuration.md](configuration.md#mail)).

1. `GET /recover` asks for the address. The login page links to it.
2. `POST /recover` always shows the same page and takes the same time. An unknown address and a disabled user get no mail.
3. The mail has the link `{MINIAUTH_PUBLIC_URL}/recover/{token}`. It works once and expires after 30 minutes.
4. `POST /recover/reset` sets the new password. It deletes every session of the user and every other open link. A second mail says that the password changed.

Personal access tokens stay valid after a reset. Recovery requests have their own backoff per address and per client IP, with the password rules.
