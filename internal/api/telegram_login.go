package api

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/popoffvg/sfsm"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/telegram"
	"github.com/popoffvg/miniauth/internal/views"
)

// TelegramCallbackPath is the data-auth-url path of the widget. The bot domain MUST be the host of MINIAUTH_PUBLIC_URL.
const TelegramCallbackPath = "/login/telegram/callback"

// telegramCallbackRequest documents the query of GET /login/telegram/callback.
// Telegram can add fields. Every field takes part in the hash check.
type telegramCallbackRequest struct {
	ID        string `query:"id" required:"true" description:"The Telegram user id."`
	FirstName string `query:"first_name"`
	LastName  string `query:"last_name"`
	Username  string `query:"username"`
	PhotoURL  string `query:"photo_url"`
	AuthDate  string `query:"auth_date" required:"true" description:"Unix seconds when Telegram signed the data."`
	Hash      string `query:"hash" required:"true" description:"Hex HMAC-SHA256 of the other fields, keyed with the SHA-256 of the bot token."`
}

// WithTelegram offers the Telegram widget on the login page.
// links keeps an unknown Telegram account until a password login in the same browser.
func WithTelegram(step *telegram.Step, links *identitylink.Service) RouterOption {
	return func(s *service) {
		s.telegram = step
		s.links = links
	}
}

// telegramOffered needs the public URL: the widget redirects to an absolute callback URL.
func (s *service) telegramOffered() bool {
	return s.telegram != nil && s.links != nil && s.publicURL.Origin() != ""
}

func (s *service) showTelegramWidget(view *views.Page) {
	view.Telegram = views.TelegramWidget{BotName: s.telegram.BotName(), AuthURL: s.publicURL.Origin() + TelegramCallbackPath}
}

// telegramCallback checks the widget data for the flow in the flow cookie.
// A linked account completes the step. An unknown account starts no session: it becomes a pending link.
// The query MUST NOT be logged: it is the proof of one login until it is used.
func (s *service) telegramCallback(w http.ResponseWriter, r *http.Request) {
	if s.flows == nil || s.telegram == nil || s.links == nil {
		renderDenied(w, r, http.StatusServiceUnavailable, msgTelegramUnavailable)
		return
	}
	id, secret, err := flowFromRequest(r)
	if err != nil {
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	machine, err := s.flows.Open(r.Context(), id, secret)
	if errors.Is(err, loginflow.ErrFlowNotFound) {
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	}
	if err != nil {
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: open login", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	defer func() { _ = machine.Close() }()

	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		s.renderSteps(w, r, http.StatusBadRequest, machine.Get(), msgTelegramFailed)
		return
	}
	data, err := telegram.ParseAuthData(query)
	if err != nil {
		s.renderSteps(w, r, http.StatusBadRequest, machine.Get(), msgTelegramFailed)
		return
	}
	outcome, err := s.telegram.Finish(r.Context(), machine, data)
	switch {
	case errors.Is(err, telegram.ErrBadHash), errors.Is(err, telegram.ErrStale), errors.Is(err, telegram.ErrReplay):
		loggerFrom(r.Context()).WarnContext(r.Context(), "miniauth: telegram data refused", "err", err)
		s.renderSteps(w, r, http.StatusBadRequest, machine.Get(), msgTelegramFailed)
		return
	case errors.Is(err, sfsm.ErrStaleState), errors.Is(err, loginflow.ErrNoTransition), errors.Is(err, loginflow.ErrFlowNotFound):
		clearFlowCookie(w)
		renderDenied(w, r, http.StatusBadRequest, msgFlowExpired)
		return
	case err != nil:
		loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: telegram step", "err", err)
		renderDenied(w, r, http.StatusInternalServerError, msgLoginFailed)
		return
	}
	if !outcome.Linked() {
		s.rememberPendingLink(w, r, outcome.Unlinked, machine.Get(), msgLinkTelegram)
		return
	}
	s.finishStep(w, r, outcome.UserID, machine.Get())
}
