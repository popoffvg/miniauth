// Package telegram is the Telegram step of the login flow: the Telegram Login Widget in redirect mode.
// Telegram sends the user fields and a hash as the query of the callback. The hash is an HMAC-SHA256
// of the fields, keyed with the SHA-256 of the bot token. Only the `id` field links a Telegram account to a user.
package telegram
