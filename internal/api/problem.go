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

	"github.com/popoffvg/miniauth/internal/access"
	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

type problemBody struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func writeProblem(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problemBody{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

var (
	errBadJSON          = errors.New("api: request body is not valid JSON")
	errTooLarge         = errors.New("api: request body is too large")
	errUnsupportedMedia = errors.New("api: content type must be application/json")
)

// decodeJSON reads one JSON object. Only white space may follow it.
// The caller maps the error to 400, 413, or 415.
// The buffer is cleared because it can hold a password.
func decodeJSON[T any](w http.ResponseWriter, r *http.Request, maxBytes int64) (T, error) {
	var zero T
	if !jsonContentType(r.Header.Get("Content-Type")) {
		return zero, errUnsupportedMedia
	}
	reader := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = reader.Close() }()
	var payload []byte
	defer func() { clear(payload) }()
	var err error
	payload, err = io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return zero, errTooLarge
		}
		return zero, errBadJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var body T
	if err = decoder.Decode(&body); err != nil {
		if domainError(err) {
			return zero, fmt.Errorf("api: decode json: %w", err)
		}
		return zero, errBadJSON
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return zero, errBadJSON
	}
	return body, nil
}

func writeDecodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUnsupportedMedia):
		writeProblem(w, http.StatusUnsupportedMediaType, "The content type must be application/json.")
	case errors.Is(err, errTooLarge):
		writeProblem(w, http.StatusRequestEntityTooLarge, "The request body is too large.")
	case errors.Is(err, errBadJSON):
		writeProblem(w, http.StatusBadRequest, "The request body is not valid JSON.")
	default:
		writeProblem(w, http.StatusBadRequest, "The request body is not valid JSON.")
	}
}

func domainError(err error) bool {
	return errors.Is(err, users.ErrInvalidLogin) ||
		errors.Is(err, users.ErrEmptyPassword) ||
		errors.Is(err, users.ErrPasswordTooLong) ||
		errors.Is(err, tokens.ErrInvalid) ||
		errors.Is(err, tokens.ErrName) ||
		errors.Is(err, tokens.ErrScope) ||
		errors.Is(err, groups.ErrName) ||
		errors.Is(err, access.ErrResourceName) ||
		errors.Is(err, access.ErrResourceURL) ||
		errors.Is(err, access.ErrHost) ||
		errors.Is(err, access.ErrPathPrefix) ||
		errors.Is(err, access.ErrExpiryTime) ||
		errors.Is(err, access.ErrExpiry)
}

func jsonContentType(header string) bool {
	mediaType, params, err := mime.ParseMediaType(header)
	if err != nil || mediaType != "application/json" {
		return false
	}
	charset, ok := params["charset"]
	return !ok || strings.EqualFold(charset, "utf-8")
}
