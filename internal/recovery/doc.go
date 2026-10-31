// Package recovery is password recovery by email.
// A reset link holds a random token. The database stores only its SHA-256.
// Mail goes out from a background queue, so the reply to a request takes the same time for a known and an unknown address.
package recovery
