package oauth

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"uuid"
)

// MaxClientNameRunes is the longest client name. It is also the longest token name,
// so the access token of a client carries the client name.
const MaxClientNameRunes = 64

// ClientID identifies one registered client. It is not a secret: a client sends it in the clear.
type ClientID uuid.UUID

// NewClientID is random: a client id tells nothing about other clients.
func NewClientID() ClientID {
	return ClientID(uuid.New())
}

// ClientIDFromBytes reads a stored id. It does not check that the client exists.
func ClientIDFromBytes(b [16]byte) ClientID {
	return ClientID(b)
}

// ParseClientID reads the text form. A malformed id is ErrClientNotFound: no client has it.
func ParseClientID(raw string) (ClientID, error) {
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return ClientID{}, ErrClientNotFound
	}
	return ClientID(parsed), nil
}

func (id ClientID) String() string {
	return uuid.UUID(id).String()
}

// Bytes is the form the database stores.
func (id ClientID) Bytes() [16]byte {
	return uuid.UUID(id)
}

// MarshalText writes the value a client sends as client_id.
func (id ClientID) MarshalText() ([]byte, error) {
	text, err := uuid.UUID(id).MarshalText()
	if err != nil {
		return nil, fmt.Errorf("oauth: client id: %w", err)
	}
	return text, nil
}

// ClientName is the name the consent page shows, for example "Claude".
type ClientName struct {
	value string
}

// ParseClientName trims raw. A name has 1 to 64 characters and no control character.
func ParseClientName(raw string) (ClientName, error) {
	s := strings.TrimSpace(raw)
	n := utf8.RuneCountInString(s)
	if !utf8.ValidString(s) || n < 1 || n > MaxClientNameRunes || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return ClientName{}, ErrClientName
	}
	return ClientName{value: s}, nil
}

func (n ClientName) String() string {
	return n.value
}

// MarshalText writes the name the consent page shows.
func (n ClientName) MarshalText() ([]byte, error) {
	return []byte(n.value), nil
}

// UnmarshalText refuses a JSON name that breaks the name rules, so the admin API answers 400.
func (n *ClientName) UnmarshalText(text []byte) error {
	parsed, err := ParseClientName(string(text))
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// Client is an MCP client that an admin registered. It has no secret: PKCE binds each code to the client that asked.
type Client struct {
	ID           ClientID
	Name         ClientName
	RedirectURIs []RedirectURI
	CreatedAt    time.Time
}

// Allows reports whether the client registered requested.
func (c Client) Allows(requested RedirectURI) bool {
	return slices.ContainsFunc(c.RedirectURIs, func(registered RedirectURI) bool {
		return registered.Matches(requested)
	})
}
