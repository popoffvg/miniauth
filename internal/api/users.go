package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/popoffvg/miniauth/internal/user"
)

// maxCreateUserBody is large enough for the longest login and password.
// A larger body is refused before it is decoded.
const maxCreateUserBody = 8 << 10

// createdUser is the 201 body. It has no password.
type createdUser struct {
	ID    user.UserID `json:"id"`
	Login user.Login  `json:"login"`
}

// loginField is the login text in a JSON body, before the login rules run.
type loginField string

// passwordField is the password text in a JSON body.
// Printing it yields "redacted".
type passwordField struct {
	raw string
}

// String returns "redacted".
func (p passwordField) String() string {
	return "redacted"
}

// GoString returns "redacted".
func (p passwordField) GoString() string {
	return "redacted"
}

// Format prints "redacted" for every verb, so a log cannot show the password.
func (p passwordField) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redacted")
}

// UnmarshalJSON stores a JSON string.
func (p *passwordField) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		p.raw = ""
		return nil
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return errors.New("api: password must be a string")
	}
	p.raw = raw
	return nil
}

// MarshalJSON writes "redacted". The password MUST NOT be encoded.
func (p passwordField) MarshalJSON() ([]byte, error) {
	return []byte(`"redacted"`), nil
}

type createUserRequest struct {
	Login    loginField    `json:"login"`
	Password passwordField `json:"password"`
}

func (r *Router) createUser(w http.ResponseWriter, req *http.Request) {
	token, ok := bearerToken(req)
	if !ok || !r.admin.Matches(token) {
		writeProblem(w, http.StatusUnauthorized, "The bearer token is missing or wrong.")
		return
	}
	if !jsonContentType(req.Header.Get("Content-Type")) {
		writeProblem(w, http.StatusUnsupportedMediaType, "The content type must be application/json.")
		return
	}

	body, err := decodeCreateUser(w, req)
	if err != nil {
		r.writeCreateUserError(w, err)
		return
	}
	login, err := user.ParseLogin(string(body.Login))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "The login is not valid.")
		return
	}
	password, err := user.NewPassword(body.Password.raw)
	if err != nil {
		r.writeCreateUserError(w, err)
		return
	}
	if r.users == nil {
		r.writeCreateUserError(w, errors.New("api: user service is missing"))
		return
	}

	created, err := r.users.Create(req.Context(), login, password)
	if err != nil {
		r.writeCreateUserError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdUser{ID: created.ID, Login: created.Login})
}

func decodeCreateUser(w http.ResponseWriter, req *http.Request) (createUserRequest, error) {
	reader := http.MaxBytesReader(w, req.Body, maxCreateUserBody)
	defer func() { _ = reader.Close() }()
	// The body holds the password. Clear this buffer when the function returns.
	var payload []byte
	defer func() { clear(payload) }()
	var err error
	payload, err = io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return createUserRequest{}, errTooLarge
		}
		return createUserRequest{}, errBadJSON
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var body createUserRequest
	if err = decoder.Decode(&body); err != nil {
		return createUserRequest{}, errBadJSON
	}
	if decoder.More() {
		return createUserRequest{}, errBadJSON
	}
	return body, nil
}

func jsonContentType(header string) bool {
	mediaType, params, err := mime.ParseMediaType(header)
	if err != nil || mediaType != "application/json" {
		return false
	}
	charset, ok := params["charset"]
	return !ok || strings.EqualFold(charset, "utf-8")
}

var (
	errBadJSON  = errors.New("api: request body is not valid JSON")
	errTooLarge = errors.New("api: request body is too large")
)

func (r *Router) writeCreateUserError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBadJSON):
		writeProblem(w, http.StatusBadRequest, "The request body is not valid JSON.")
	case errors.Is(err, errTooLarge):
		writeProblem(w, http.StatusRequestEntityTooLarge, "The request body is too large.")
	case errors.Is(err, user.ErrInvalidLogin):
		writeProblem(w, http.StatusBadRequest, "The login is not valid.")
	case errors.Is(err, user.ErrEmptyPassword):
		writeProblem(w, http.StatusBadRequest, "The password is empty.")
	case errors.Is(err, user.ErrPasswordTooLong):
		writeProblem(w, http.StatusBadRequest, "The password is too long.")
	case errors.Is(err, user.ErrLoginTaken):
		writeProblem(w, http.StatusConflict, "The login already exists.")
	default:
		// The repository error does not include the password or the hash.
		r.log.Error("miniauth: create user", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The user was not created.")
	}
}
