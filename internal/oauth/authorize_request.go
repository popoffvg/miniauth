package oauth

import (
	"strings"
	"unicode"

	"github.com/popoffvg/miniauth/internal/tokens"
)

// MaxStateLength is the longest state the server sends back to the client.
const MaxStateLength = 1024

// State is the value the client sends to the authorization endpoint and gets back in the redirect.
// It is the client's CSRF guard, not a secret of this server.
type State struct {
	value string
}

// ParseState reads the state. An empty state is allowed: PKCE already binds the code to the client.
func ParseState(raw string) (State, error) {
	if len(raw) > MaxStateLength || strings.IndexFunc(raw, unicode.IsControl) >= 0 {
		return State{}, ErrState
	}
	return State{value: raw}, nil
}

func (s State) String() string {
	return s.value
}

// AuthorizeRequest is a checked request of the authorization endpoint.
// Resource is the one URL prefix the access token reaches.
type AuthorizeRequest struct {
	Client      Client
	RedirectURI RedirectURI
	Challenge   Challenge
	Resource    tokens.Scope
	State       State
}
