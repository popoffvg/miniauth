package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/identitylink"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/providers/telegram"
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
	s := &service{
		passkeys:  &passkey.Service{},
		telegram:  &telegram.Step{},
		links:     &identitylink.Service{},
		publicURL: PublicURL{origin: "https://id.example.test"},
	}
	rec := httptest.NewRecorder()
	secret, err := loginflow.NewFlowSecret()
	require.NoError(t, err)
	req := withNewFlowSecret(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login", nil), secret)
	s.renderSteps(rec, req, http.StatusOK, loginflow.LoginFlow{}, "")
	body := rec.Body.String()
	assert.Contains(t, body, `name="password"`)
	assert.Contains(t, body, `data-passkey-login="`+passkeyLoginPath+`"`)
	assert.Contains(t, body, `<script src="`+passkeyScriptPath+`"></script>`)
	assert.Contains(t, body, "https://telegram.org/js/telegram-widget.js")
	csp := rec.Header().Get("Content-Security-Policy")
	assert.Contains(t, csp, "script-src 'self' https://telegram.org;")
	assert.Contains(t, csp, "connect-src 'self';")
	assert.Contains(t, csp, "frame-src https://oauth.telegram.org;")
}
