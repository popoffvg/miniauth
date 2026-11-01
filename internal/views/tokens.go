package views

import "github.com/popoffvg/miniauth/internal/tokens"

// TokenFilter is the status filter of the token table. Empty shows every token.
type TokenFilter string

// The token filters. Each is the value of the status query of GET /tokens.
const (
	TokenFilterActive  TokenFilter = "active"
	TokenFilterExpired TokenFilter = "expired"
	TokenFilterRevoked TokenFilter = "revoked"
)

// TokenChips are the filters above the token table. A filter that is not here shows every token.
var TokenChips = []FilterChip{
	{Value: "", Label: "All"},
	{Value: string(TokenFilterActive), Label: "Active"},
	{Value: string(TokenFilterExpired), Label: "Expired"},
	{Value: string(TokenFilterRevoked), Label: "Revoked"},
}

// TokenStatus is the state badge of one token row.
type TokenStatus struct {
	Filter TokenFilter
	Tone   Tone
	Label  string
}

// The token states, one badge each.
var (
	TokenActive  = TokenStatus{Filter: TokenFilterActive, Tone: ToneActive, Label: "Active"}
	TokenExpired = TokenStatus{Filter: TokenFilterExpired, Tone: ToneExpired, Label: "Expired"}
	TokenRevoked = TokenStatus{Filter: TokenFilterRevoked, Tone: ToneRevoked, Label: "Revoked"}
)

// TokenRow is one token of the table with its state.
type TokenRow struct {
	Token  tokens.Token
	Status TokenStatus
}

// TokenTable is the rows that pass the search and the filter. Total counts every token of the user.
type TokenTable struct {
	Rows   []TokenRow
	Total  int
	Query  string
	Filter TokenFilter
}

// TokenField is the form field that a refused POST /tokens names.
type TokenField string

// The fields of the token form.
const (
	TokenFieldName    TokenField = "name"
	TokenFieldScopes  TokenField = "scopes"
	TokenFieldExpires TokenField = "expires"
)

// ConsentField is one hidden field of the consent form.
type ConsentField struct {
	Name  string
	Value string
}

// TokenForm is the sent form again, so the user corrects one field and keeps the others.
type TokenForm struct {
	Name    string
	Scopes  string
	Expires string
	Field   TokenField
	Message Message
}
