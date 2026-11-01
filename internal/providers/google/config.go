package google

import (
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/loginflow"

	"github.com/popoffvg/miniauth/internal/users"
)

// GoogleIssuer is the OIDC issuer of Google accounts.
const GoogleIssuer = "https://accounts.google.com"

// ClientID is the OAuth client id. It is not a secret.
type ClientID struct {
	value string
}

// ParseClientID trims raw. An empty value is the zero ClientID.
func ParseClientID(raw string) ClientID {
	return ClientID{value: strings.TrimSpace(raw)}
}

func (c ClientID) String() string {
	return c.value
}

// ClientSecret is the OAuth client secret. Printing it yields "redacted".
type ClientSecret struct {
	users.Redacted
	value string
}

// ParseClientSecret trims raw. An empty value is the zero ClientSecret.
func ParseClientSecret(raw string) ClientSecret {
	return ClientSecret{value: strings.TrimSpace(raw)}
}

// Empty reports whether no secret is set.
func (c ClientSecret) Empty() bool {
	return c.value == ""
}

// Issuer is the OIDC issuer URL. Discovery reads Issuer + "/.well-known/openid-configuration".
type Issuer string

// RedirectURL is the callback URL that the provider sends the browser back to.
type RedirectURL string

// Config is what the step needs. HTTPClient is used for discovery, keys, and the code exchange.
// A nil HTTPClient is a client with a 10 second timeout.
// SecondFactors tells which linked users need a second step. Nil means none.
type Config struct {
	Issuer        Issuer
	ClientID      ClientID
	ClientSecret  ClientSecret
	RedirectURL   RedirectURL
	HTTPClient    *http.Client
	SecondFactors loginflow.SecondFactors
}
