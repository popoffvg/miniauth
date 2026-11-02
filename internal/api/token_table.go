package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/views"
)

// statusOf ranks a revoke above an expiry: a revoked token never works again.
func statusOf(token tokens.Token, now time.Time) views.TokenStatus {
	switch {
	case token.Revoked():
		return views.TokenRevoked
	case token.Expired(now):
		return views.TokenExpired
	default:
		return views.TokenActive
	}
}

func newTokenTable(r *http.Request, list []tokens.Token, now time.Time) views.TokenTable {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	filter := views.TokenFilter(r.URL.Query().Get("status"))
	known := false
	for _, chip := range views.TokenChips {
		known = known || chip.Value == string(filter)
	}
	if !known {
		filter = ""
	}
	table := views.TokenTable{Total: len(list), Query: query, Filter: filter}
	for _, token := range list {
		status := statusOf(token, now)
		if filter != "" && status.Filter != filter {
			continue
		}
		if !matchesQuery(query, append(token.Scopes.Strings(), token.Name.String(), token.Prefix.String())...) {
			continue
		}
		table.Rows = append(table.Rows, views.TokenRow{Token: token, Status: status})
	}
	return table
}

// tokenFieldOf is the field of each form message. A message that is not here names no field.
var tokenFieldOf = map[views.Message]views.TokenField{
	msgTokenName:      views.TokenFieldName,
	msgScopeNotValid:  views.TokenFieldScopes,
	msgExpiryNotValid: views.TokenFieldExpires,
}

func refusedTokenForm(r *http.Request, message views.Message) views.TokenForm {
	field, ok := tokenFieldOf[message]
	if !ok {
		return views.TokenForm{}
	}
	return views.TokenForm{
		Name:    r.PostForm.Get("name"),
		Scopes:  r.PostForm.Get("scopes"),
		Expires: r.PostForm.Get("expires"),
		Field:   field,
		Message: message,
	}
}

// tokenDraftFields are the token form fields that the step-up keeps in the return URL.
// None of them is a secret.
var tokenDraftFields = []string{"name", "scopes", "expires"}

// tokenDraftPath is the token page with the sent form in the query.
func tokenDraftPath(r *http.Request) string {
	draft := url.Values{}
	for _, field := range tokenDraftFields {
		if value := r.PostForm.Get(field); value != "" {
			draft.Set(field, value)
		}
	}
	if len(draft) == 0 {
		return tokensPath
	}
	return tokensPath + "?" + draft.Encode() + "#new-token"
}

// draftTokenForm fills in the token form from the query that tokenDraftPath wrote.
func draftTokenForm(r *http.Request) views.TokenForm {
	query := r.URL.Query()
	return views.TokenForm{
		Name:    query.Get("name"),
		Scopes:  query.Get("scopes"),
		Expires: query.Get("expires"),
	}
}
