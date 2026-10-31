package passkeystep

import (
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/popoffvg/miniauth/internal/sessions"
)

// relyingPartyName is the name an authenticator shows next to a passkey.
const relyingPartyName = "miniauth"

// RelyingPartyID is the domain a passkey is bound to. It has no scheme and no port.
type RelyingPartyID string

// Origin is the scheme, host, and port of the page that runs a ceremony.
type Origin string

// RelyingParty is the site the passkeys belong to.
type RelyingParty struct {
	ID     RelyingPartyID
	Origin Origin
}

// NewRelyingParty takes the id from the cookie domain without the leading dot.
// With an empty domain, the id is the host of origin, so the passkeys work on that host only.
// An IP address is not a valid id: a browser refuses it.
func NewRelyingParty(domain sessions.Domain, origin *url.URL) (RelyingParty, error) {
	if origin == nil || origin.Host == "" || (origin.Scheme != "https" && origin.Scheme != "http") {
		return RelyingParty{}, ErrRelyingParty
	}
	id := strings.TrimPrefix(domain.String(), ".")
	if id == "" {
		id = strings.ToLower(origin.Hostname())
	}
	if protocol.ValidateRPID(id) != nil {
		return RelyingParty{}, ErrRelyingParty
	}
	return RelyingParty{
		ID:     RelyingPartyID(id),
		Origin: Origin(origin.Scheme + "://" + origin.Host),
	}, nil
}
