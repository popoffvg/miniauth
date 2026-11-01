// Package oauth is the OAuth 2.1 authorization server for MCP clients.
// An admin registers each client. A user approves a client for one resource once, on the consent page.
// The token endpoint issues an access token that /auth/check reads as a personal access token,
// and a refresh token that rotates at each use.
package oauth
