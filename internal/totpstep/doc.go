// Package totpstep is the TOTP step and the recovery code step of a login flow.
// TOTP is the RFC 6238 time-based one-time code: SHA-1, 6 digits, 30 s steps.
// The step reports the result to the flow. It never starts a session.
package totpstep
