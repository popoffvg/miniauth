package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/groups"
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

// invitePathPrefix starts each invite link. The rest of the path is the invite token, a secret.
const invitePathPrefix = "/invite/"

// inviteAcceptPath is the one path under invitePathPrefix that holds no token.
const inviteAcceptPath = invitePathPrefix + "accept"

// inviteLinkPattern replaces the token of an invite link in a log line and a span.
const inviteLinkPattern = invitePathPrefix + "{token}"

// WithInvites serves the invite routes. Without them, they answer 503.
func WithInvites(invitations *invites.Service) RouterOption {
	return func(s *service) {
		s.invites = invitations
	}
}

type createInviteRequest struct {
	Group groups.Name `json:"group,omitzero" doc:"The group of the new account. Absent: users. The account also joins users."`
}

// inviteLink is the one-time link of an invite. It holds the token.
type inviteLink string

// inviteBody is the 201 body. The link is shown once: only the token hash is stored.
type inviteBody struct {
	Link      inviteLink  `json:"link" format:"uri" doc:"The public URL, /invite/, and the token. Shown once."`
	Group     groups.Name `json:"group"`
	ExpiresAt time.Time   `json:"expires_at"`
}

// inviteFormRequest documents the form of POST /invite/accept.
type inviteFormRequest struct {
	Token    string `formData:"token" required:"true"`
	Login    string `formData:"login" required:"true" minLength:"1" maxLength:"64"`
	Password string `formData:"password" required:"true" minLength:"1" maxLength:"1024" format:"password"`
}

type invitePath struct {
	Token string `path:"token"`
}

const (
	msgInviteGone         views.Message = "This invite link does not work. It was used, it expired, or it is wrong."
	msgInviteLogin        views.Message = "The login or the password does not match the rules."
	msgInviteLoginUsed    views.Message = "This login is taken. Choose another login."
	msgInviteFailed       views.Message = "The account was not created. Try again."
	msgInviteOff          views.Message = "Invites are not available."
	msgInviteSignInFailed views.Message = "Your account was created, but the sign-in failed. Sign in with your new login and password."
)

func (s *service) createInvite(w http.ResponseWriter, r *http.Request) {
	if s.invites == nil {
		writeProblem(w, http.StatusServiceUnavailable, "The invite API is not configured.")
		return
	}
	// Without a public URL the Origin check refuses every accept, so a link could never work.
	if s.publicURL.Origin() == "" {
		writeProblem(w, http.StatusServiceUnavailable, "Invite links need MINIAUTH_PUBLIC_URL.")
		return
	}
	body, err := decodeJSON[createInviteRequest](w, r, maxAccessBody)
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	invite, err := s.makeInvite(r.Context(), body.Group)
	if errors.Is(err, groups.ErrGroupNotFound) {
		writeProblem(w, http.StatusNotFound, "The group is not found.")
		return
	}
	if err != nil {
		writeAccessError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, invite)
}

// invitePage shows the account form of an open invite.
// An unknown, used, or expired token gets the same page and status, so a guess learns nothing.
func (s *service) invitePage(w http.ResponseWriter, r *http.Request) {
	setInviteHeaders(w)
	if s.invites == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgInviteOff)
		return
	}
	token, ok := s.openInvite(w, r, r.PathValue("token"))
	if !ok {
		return
	}
	renderPage(w, r, http.StatusOK, views.PageInvite, views.Page{Invite: token})
}

// acceptInvite creates the account in the group of the invite, starts a session, and opens the overview.
func (s *service) acceptInvite(w http.ResponseWriter, r *http.Request) {
	setInviteHeaders(w)
	if !s.sameOrigin(r) {
		renderDenied(w, r, http.StatusForbidden, msgCrossOrigin)
		return
	}
	if s.invites == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgInviteOff)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBody)
	if r.ParseForm() != nil {
		renderDenied(w, r, http.StatusBadRequest, msgBadForm)
		return
	}
	token, ok := s.openInvite(w, r, r.PostForm.Get("token"))
	if !ok {
		return
	}
	login, loginErr := users.ParseLogin(r.PostForm.Get("login"))
	password, passwordErr := users.NewPassword(r.PostForm.Get("password"))
	if loginErr != nil || passwordErr != nil {
		renderPage(w, r, http.StatusBadRequest, views.PageInvite, views.Page{Invite: token, Message: msgInviteLogin})
		return
	}
	accepted, err := s.invites.Accept(r.Context(), token, login, password)
	switch {
	case errors.Is(err, invites.ErrInviteGone):
		renderDenied(w, r, http.StatusGone, msgInviteGone)
		return
	case errors.Is(err, users.ErrLoginTaken):
		renderPage(w, r, http.StatusConflict, views.PageInvite, views.Page{Invite: token, Message: msgInviteLoginUsed})
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: accept invite", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgInviteFailed)
		return
	}
	if err := s.startBrowserSession(w, r, accepted.User.ID, loginflow.Factors(loginflow.FactorPassword)); err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: invite session", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgInviteSignInFailed)
		return
	}
	http.Redirect(w, r, s.publicURL.Origin()+"/", http.StatusSeeOther)
}

// openInvite renders the gone page and returns false unless raw is the token of an open invite.
func (s *service) openInvite(w http.ResponseWriter, r *http.Request, raw string) (invites.Token, bool) {
	token, err := invites.ParseToken(raw)
	if err == nil {
		_, err = s.invites.Open(r.Context(), token)
	}
	switch {
	case errors.Is(err, invites.ErrInviteGone):
		renderDenied(w, r, http.StatusGone, msgInviteGone)
		return invites.Token{}, false
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: open invite", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgInviteFailed)
		return invites.Token{}, false
	}
	return token, true
}

// setInviteHeaders keeps the token out of the Referer of the next request and out of every cache.
func setInviteHeaders(w http.ResponseWriter) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

// makeInvite stores an invite and returns its link. The link holds the token, so the caller shows it once.
func (s *service) makeInvite(ctx context.Context, group groups.Name) (inviteBody, error) {
	token, invite, err := s.invites.Create(ctx, group)
	if err != nil {
		return inviteBody{}, err
	}
	return inviteBody{
		Link:      inviteLink(s.publicURL.Origin() + invitePathPrefix + token.Reveal()),
		Group:     invite.Group,
		ExpiresAt: invite.ExpiresAt,
	}, nil
}
