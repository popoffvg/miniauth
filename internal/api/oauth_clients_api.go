package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/oauth"
)

// oauthClientsPath is the admin API of the OAuth clients.
const oauthClientsPath = "/api/v1/oauth/clients"

type createOAuthClientRequest struct {
	Name         oauth.ClientName    `json:"name" required:"true" minLength:"1" maxLength:"64"`
	RedirectURIs []oauth.RedirectURI `json:"redirect_uris" required:"true" minItems:"1" description:"Each URI is https, or http on localhost, 127.0.0.1, or [::1]. An http loopback URI matches on any port."`
}

type oauthClientBody struct {
	ClientID     oauth.ClientID      `json:"client_id"`
	Name         oauth.ClientName    `json:"name"`
	RedirectURIs []oauth.RedirectURI `json:"redirect_uris"`
	CreatedAt    time.Time           `json:"created_at"`
}

type oauthClientList struct {
	Clients []oauthClientBody `json:"clients"`
}

type oauthClientPath struct {
	ID string `path:"id" format:"uuid"`
}

func newOAuthClientBody(client oauth.Client) oauthClientBody {
	return oauthClientBody{ClientID: client.ID, Name: client.Name, RedirectURIs: client.RedirectURIs, CreatedAt: client.CreatedAt}
}

// oauthAdminReady writes 503 and returns false when the router has no OAuth service.
func (s *service) oauthAdminReady(w http.ResponseWriter) bool {
	if s.oauth == nil {
		writeProblem(w, http.StatusServiceUnavailable, "The OAuth API is not configured.")
		return false
	}
	return true
}

func (s *service) createOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !s.oauthAdminReady(w) {
		return
	}
	body, err := decodeJSON[createOAuthClientRequest](w, r, maxAccessBody)
	if err != nil {
		writeOAuthClientError(w, r, err)
		return
	}
	client, err := s.oauth.RegisterClient(r.Context(), body.Name, body.RedirectURIs)
	if err != nil {
		writeOAuthClientError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, newOAuthClientBody(client))
}

func (s *service) listOAuthClients(w http.ResponseWriter, r *http.Request) {
	if !s.oauthAdminReady(w) {
		return
	}
	clients, err := s.oauth.ListClients(r.Context())
	if err != nil {
		writeOAuthClientError(w, r, err)
		return
	}
	list := oauthClientList{Clients: make([]oauthClientBody, 0, len(clients))}
	for _, client := range clients {
		list.Clients = append(list.Clients, newOAuthClientBody(client))
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *service) deleteOAuthClient(w http.ResponseWriter, r *http.Request) {
	if !s.oauthAdminReady(w) {
		return
	}
	id, err := oauth.ParseClientID(r.PathValue("id"))
	if err == nil {
		err = s.oauth.DeleteClient(r.Context(), id)
	}
	if err != nil {
		writeOAuthClientError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeOAuthClientError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errUnsupportedMedia) || errors.Is(err, errTooLarge) || errors.Is(err, errBadJSON):
		writeDecodeError(w, err)
	case errors.Is(err, oauth.ErrClientName):
		writeProblem(w, http.StatusBadRequest, "The client name must have 1 to 64 characters.")
	case errors.Is(err, oauth.ErrRedirectURI):
		writeProblem(w, http.StatusBadRequest, "Each redirect URI must be https, or http on a loopback host, with no fragment. Give at least one.")
	case errors.Is(err, oauth.ErrClientNotFound):
		writeProblem(w, http.StatusNotFound, "The OAuth client is not found.")
	default:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: oauth client api", "err", err)
		writeProblem(w, http.StatusInternalServerError, "The OAuth client change failed.")
	}
}
