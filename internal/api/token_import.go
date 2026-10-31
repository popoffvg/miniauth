package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// maxImportTokenBody is large enough for a login, a name, a token, and many scopes.
const maxImportTokenBody = 16 << 10

// importTokenRequest is the JSON body and the OpenAPI request schema.
// The tags describe the shape. The tokens and users parsers decide acceptance.
type importTokenRequest struct {
	User   users.Login    `json:"user" required:"true" minLength:"1" maxLength:"64" doc:"Login of the token owner."`
	Name   tokens.Name    `json:"name" required:"true" minLength:"1" maxLength:"64"`
	Scopes []tokens.Scope `json:"scopes" required:"true" minItems:"1" nullable:"false" doc:"http or https URL prefixes. The token reaches only URLs under them."`
	Token  tokens.Secret  `json:"token" required:"true" format:"password" pattern:"^idp_[0-9A-Za-z]{43}$" doc:"The clear token. Only its SHA-256 is stored. The reply does not contain it."`
}

// importedToken is the 200 and 201 body. It has no token.
type importedToken struct {
	ID     tokens.ID      `json:"id" format:"uuid"`
	Name   tokens.Name    `json:"name"`
	Prefix tokens.Prefix  `json:"prefix" doc:"The first 8 characters of the token."`
	Scopes []tokens.Scope `json:"scopes" nullable:"false"`
}

// errNoScope means the import body has an empty scope list.
// An empty list reaches every URL, so an import MUST name at least one scope.
var errNoScope = errors.New("api: import needs a scope")

func (s *service) importToken(w http.ResponseWriter, r *http.Request) {
	body, err := decodeJSON[importTokenRequest](w, r, maxImportTokenBody)
	if err != nil {
		writeImportError(w, r, err)
		return
	}
	if len(body.Scopes) == 0 {
		writeImportError(w, r, errNoScope)
		return
	}
	owner, err := s.accounts.FindByLogin(r.Context(), body.User)
	if err != nil {
		writeImportError(w, r, err)
		return
	}
	token, created, err := s.tokens.Import(r.Context(), owner.ID, body.Name, body.Scopes, body.Token)
	if err != nil {
		writeImportError(w, r, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, importedToken{ID: token.ID, Name: token.Name, Prefix: token.Prefix, Scopes: token.Scopes})
}

// writeImportError MUST NOT write the body or the token: err comes from parsers that do not echo the value.
func writeImportError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errUnsupportedMedia), errors.Is(err, errTooLarge), errors.Is(err, errBadJSON):
		writeDecodeError(w, err)
	case errors.Is(err, users.ErrInvalidLogin):
		writeProblem(w, http.StatusBadRequest, "The user login is not valid.")
	case errors.Is(err, tokens.ErrInvalid):
		writeProblem(w, http.StatusBadRequest, "The token format is not valid.")
	case errors.Is(err, tokens.ErrName):
		writeProblem(w, http.StatusBadRequest, "The token name is not valid.")
	case errors.Is(err, tokens.ErrScope):
		writeProblem(w, http.StatusBadRequest, "A scope is not an http or https URL prefix.")
	case errors.Is(err, errNoScope):
		writeProblem(w, http.StatusBadRequest, "The scope list is empty.")
	case errors.Is(err, users.ErrNotFound), errors.Is(err, tokens.ErrUnknownUser):
		writeProblem(w, http.StatusNotFound, "The user is not known.")
	case errors.Is(err, tokens.ErrDuplicate):
		writeProblem(w, http.StatusConflict, "Another user has this token.")
	default:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: import token", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The token was not imported.")
	}
}
