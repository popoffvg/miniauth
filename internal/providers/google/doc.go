// Package google is the Google step of the login flow: the OIDC authorization code flow with PKCE.
// Only the `sub` claim links a Google account to a user. The email and `email_verified` are not read.
//
// The PKCE verifier is split: the browser cookie holds the verifier, and login_flows.challenge
// holds its SHA-256 next to the hashes of the state and the nonce. A copy of the database alone
// cannot finish a login, and a stolen cookie alone has no flow to finish.
package google
