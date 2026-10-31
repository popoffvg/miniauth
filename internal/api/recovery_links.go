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

// secretLink is a path prefix whose next segment is a secret token.
// formPath is the one path under prefix that holds no token.
type secretLink struct {
	prefix   string
	formPath string
	pattern  string
}

var secretLinks = []secretLink{
	{prefix: resetLinkPrefix, formPath: resetFormPath, pattern: resetLinkPattern},
	{prefix: invitePathPrefix, formPath: inviteAcceptPath, pattern: inviteLinkPattern},
}

// loggedPath replaces the token of a secret link with the route pattern.
// A log line and a span MUST NOT hold the token.
func loggedPath(path string) string {
	for _, link := range secretLinks {
		if strings.HasPrefix(path, link.prefix) && path != link.formPath {
			return link.pattern
		}
	}
	return path
}
