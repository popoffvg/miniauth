package api

import (
	"strings"

	"github.com/popoffvg/miniauth/internal/recovery"
)

const (
	recoverPath      = "/recover"
	resetLinkPrefix  = recoverPath + "/"
	resetFormPath    = recoverPath + "/reset"
	resetLinkPattern = resetLinkPrefix + "{token}"
	tokensPagePath   = "/tokens"
)

var _ recovery.Links = PublicURL{}

// ResetLink is the link in a recovery mail. The token is in the path, so a mail client can open it.
func (u PublicURL) ResetLink(token recovery.Token) string {
	return u.origin + resetLinkPrefix + token.LinkValue()
}

// TokensPage is the page that lists the personal access tokens of the user.
func (u PublicURL) TokensPage() string {
	return u.origin + tokensPagePath
}

// loggedPath replaces the token of a reset link with the route pattern.
// A log line and a span MUST NOT hold the token.
func loggedPath(path string) string {
	rest, ok := strings.CutPrefix(path, resetLinkPrefix)
	if !ok || rest == strings.TrimPrefix(resetFormPath, resetLinkPrefix) {
		return path
	}
	return resetLinkPattern
}
