package api

import (
	"net/url"
	"strings"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/sessions"
)

// ParseReturnURL keeps raw only when it is an https URL whose host the session cookie reaches:
// a host under domain, or the public URL host when domain is empty.
// Any other value is the public URL root, so a login cannot send the browser to another site.
func ParseReturnURL(raw string, domain sessions.Domain, public PublicURL) loginflow.ReturnURL {
	fallback := loginflow.ReturnURL(public.Root())
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Opaque != "" {
		return fallback
	}
	if !forwardedHostAllowed(parsed.Host, domain, public) {
		return fallback
	}
	returnURL, err := loginflow.NewReturnURL(parsed.String())
	if err != nil {
		return fallback
	}
	return returnURL
}
