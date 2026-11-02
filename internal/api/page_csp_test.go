package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/loginflow/loginflowtest"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/providers/telegram"
	"github.com/popoffvg/miniauth/internal/providers/telegram/telegramtest"
	"github.com/popoffvg/miniauth/internal/users"
	"github.com/popoffvg/miniauth/internal/views"
)

func TestPageCSPAddsTheSourcesOfEachFeature(t *testing.T) {
	bot, err := telegram.ParseBotName("minibot")
	require.NoError(t, err)
	widget := views.TelegramWidget{BotName: bot, AuthURL: "https://id.example.test" + TelegramCallbackPath}
	tests := []struct {
		name string
		view views.Page
		want string
	}{
		{name: "no feature", view: views.Page{}, want: "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"},
		{name: "passkey script", view: views.Page{Script: true}, want: "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"},
		{name: "telegram widget", view: views.Page{Telegram: widget}, want: "default-src 'none'; script-src https://telegram.org; frame-src https://oauth.telegram.org; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"},
		{name: "both", view: views.Page{Script: true, Telegram: widget}, want: "default-src 'none'; script-src 'self' https://telegram.org; connect-src 'self'; frame-src https://oauth.telegram.org; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, pageCSPOf(tt.view), tt.name)
	}
	assert.Equal(t, scriptPageCSP, pageCSPOf(views.Page{Script: true}))
	assert.Equal(t, telegramPageCSP, pageCSPOf(views.Page{Telegram: widget}))
}

func TestLoginPageWithPasskeyAndTelegramAllowsBothScripts(t *testing.T) {
	bot, err := telegram.ParseBotName(telegramtest.BotName)
	require.NoError(t, err)
	steps := loginflowtest.NewStepStore()
	step, err := telegram.NewStep(telegram.Config{BotName: bot, BotToken: telegram.ParseBotToken(telegramtest.BotToken)}, noIdentities{}, noProofs{}, steps)
	require.NoError(t, err)
	flowID, err := loginflow.NewFlowID()
	require.NoError(t, err)
	s := &service{
		passkeys:  &passkey.Service{},
		telegram:  step,
		links:     &identitylink.Service{},
		publicURL: PublicURL{origin: "https://id.example.test"},
	}
	rec := httptest.NewRecorder()
	secret, err := loginflow.NewFlowSecret()
	require.NoError(t, err)
	req := withNewFlowSecret(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil), secret)
	s.renderSteps(rec, req, http.StatusOK, loginflow.LoginFlow{ID: flowID}, "")
	body := rec.Body.String()
	assert.Contains(t, body, `name="password"`)
	assert.Contains(t, body, `data-passkey-login="`+passkeyLoginPath+`"`)
	assert.Contains(t, body, `<script src="`+passkeyScriptPath+`"></script>`)
	assert.Contains(t, body, "https://telegram.org/js/telegram-widget.js")
	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "script-src 'self' https://telegram.org;")
	assert.Contains(t, csp, "connect-src 'self';")
	assert.Contains(t, csp, "frame-src https://oauth.telegram.org;")
	shown, err := steps.LoadStep(t.Context(), flowID)
	require.NoError(t, err)
	assert.Equal(t, loginflow.StepState(telegram.StepWidgetShown), shown, "showing the widget starts the Telegram step")
}

// noIdentities knows no account.
type noIdentities struct{}

func (noIdentities) FindExternalIdentity(context.Context, users.ExternalAccount) (users.Identity, error) {
	return users.Identity{}, users.ErrNotFound
}

// noProofs stores nothing.
type noProofs struct{}

func (noProofs) Use(context.Context, telegram.ProofHash, time.Time) error { return nil }
func (noProofs) Release(context.Context, telegram.ProofHash) error        { return nil }
func (noProofs) Cleanup(context.Context, time.Time) error                 { return nil }
