package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/tokens"
)

// tokenFilter is the status filter of the token table. Empty shows every token.
type tokenFilter string

const (
	tokenFilterActive  tokenFilter = "active"
	tokenFilterExpired tokenFilter = "expired"
	tokenFilterRevoked tokenFilter = "revoked"
)

var tokenChips = []filterChip{
	{Value: "", Label: "All"},
	{Value: string(tokenFilterActive), Label: "Active"},
	{Value: string(tokenFilterExpired), Label: "Expired"},
	{Value: string(tokenFilterRevoked), Label: "Revoked"},
}

// tokenStatus is the state badge of one token row.
type tokenStatus struct {
	Filter tokenFilter
	Tone   badgeTone
	Label  string
}

var (
	tokenActive  = tokenStatus{Filter: tokenFilterActive, Tone: toneActive, Label: "Active"}
	tokenExpired = tokenStatus{Filter: tokenFilterExpired, Tone: toneExpired, Label: "Expired"}
	tokenRevoked = tokenStatus{Filter: tokenFilterRevoked, Tone: toneRevoked, Label: "Revoked"}
)

// statusOf ranks a revoke above an expiry: a revoked token never works again.
func statusOf(token tokens.Token, now time.Time) tokenStatus {
	switch {
	case token.Revoked():
		return tokenRevoked
	case token.Expired(now):
		return tokenExpired
	default:
		return tokenActive
	}
}

type tokenRow struct {
	Token  tokens.Token
	Status tokenStatus
}

// tokenTable is the rows that pass the search and the filter. Total counts every token of the user.
type tokenTable struct {
	Rows   []tokenRow
	Total  int
	Query  string
	Filter tokenFilter
}

func newTokenTable(r *http.Request, list []tokens.Token, now time.Time) tokenTable {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := tokenFilter(r.URL.Query().Get("status"))
	known := false
	for _, chip := range tokenChips {
		known = known || chip.Value == string(filter)
	}
	if !known {
		filter = ""
	}
	table := tokenTable{Total: len(list), Query: query, Filter: filter}
	for _, token := range list {
		status := statusOf(token, now)
		if filter != "" && status.Filter != filter {
			continue
		}
		if !matchesQuery(query, append(token.Scopes.Strings(), token.Name.String(), token.Prefix.String())...) {
			continue
		}
		table.Rows = append(table.Rows, tokenRow{Token: token, Status: status})
	}
	return table
}

// tokenField is the form field that a refused POST /tokens names.
type tokenField string

const (
	tokenFieldName    tokenField = "name"
	tokenFieldScopes  tokenField = "scopes"
	tokenFieldExpires tokenField = "expires"
)

// tokenFieldOf is the field of each form message. A message that is not here names no field.
var tokenFieldOf = map[pageMessage]tokenField{
	msgTokenName:      tokenFieldName,
	msgScopeNotValid:  tokenFieldScopes,
	msgExpiryNotValid: tokenFieldExpires,
}

// tokenForm is the sent form again, so the user corrects one field and keeps the others.
type tokenForm struct {
	Name    string
	Scopes  string
	Expires string
	Field   tokenField
	Message pageMessage
}

func refusedTokenForm(r *http.Request, message pageMessage) tokenForm {
	field, ok := tokenFieldOf[message]
	if !ok {
		return tokenForm{}
	}
	return tokenForm{
		Name:    r.PostForm.Get("name"),
		Scopes:  r.PostForm.Get("scopes"),
		Expires: r.PostForm.Get("expires"),
		Field:   field,
		Message: message,
	}
}
