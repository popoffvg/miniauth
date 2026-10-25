package api

import (
	"errors"
	"net/http"

	"github.com/popoffvg/miniauth/internal/users"
)

// maxCreateUserBody is large enough for the longest login and password.
const maxCreateUserBody = 8 << 10

// createUserRequest is the JSON body and the OpenAPI request schema.
// The tags describe the shape. ParseLogin and NewPassword decide acceptance.
type createUserRequest struct {
	Login    users.Login    `json:"login" required:"true" minLength:"1" maxLength:"64" pattern:"^[A-Za-z0-9](?:[A-Za-z0-9._@+-]{0,62}[A-Za-z0-9])?$" doc:"Stored in lower case."`
	Password users.Password `json:"password" required:"true" minLength:"1" maxLength:"1024" format:"password" doc:"Stored as an argon2id PHC string."`
}

// createdUser is the 201 body. It has no password.
type createdUser struct {
	ID    users.ID    `json:"id" format:"uuid"`
	Login users.Login `json:"login"`
}

func (s *service) createUser(w http.ResponseWriter, r *http.Request) {
	body, err := decodeJSON[createUserRequest](w, r, maxCreateUserBody)
	if err != nil {
		writeCreateError(w, r, err)
		return
	}
	if s.accounts == nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: create user", "err", errors.New("api: user service is missing"))
		writeProblem(w, http.StatusInternalServerError, "The user was not created.")
		return
	}
	created, err := s.accounts.Create(r.Context(), body.Login, body.Password)
	if err != nil {
		writeCreateError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdUser{ID: created.ID, Login: created.Login})
}

func writeCreateError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errUnsupportedMedia), errors.Is(err, errTooLarge), errors.Is(err, errBadJSON):
		writeDecodeError(w, err)
	case errors.Is(err, users.ErrInvalidLogin):
		writeProblem(w, http.StatusBadRequest, "The login is not valid.")
	case errors.Is(err, users.ErrEmptyPassword):
		writeProblem(w, http.StatusBadRequest, "The password is empty.")
	case errors.Is(err, users.ErrPasswordTooLong):
		writeProblem(w, http.StatusBadRequest, "The password is too long.")
	case errors.Is(err, users.ErrLoginTaken):
		writeProblem(w, http.StatusConflict, "The login already exists.")
	default:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: create user", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The user was not created.")
	}
}
