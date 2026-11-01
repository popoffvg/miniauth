package views

import (
	"github.com/popoffvg/miniauth/internal/invites"
	"github.com/popoffvg/miniauth/internal/providers/telegram"
	"github.com/popoffvg/miniauth/internal/providers/totp"
	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/tokens"
	"github.com/popoffvg/miniauth/internal/users"
)

// Message is a sentence a page shows to the user. It MUST NOT tell which logins exist,
// except on the invite form, which needs an open invite.
type Message string

// Page is the data of every page that a PageName names. A page reads only the fields it needs.
type Page struct {
	// Shell is the signed-in user and the menu. A page of the app shell MUST have it.
	Shell   Shell
	Message Message
	// Notice is the result of the last change, from the done query flag.
	Notice Message
	// Prompt tells why the page asks for something. It is not an error.
	Prompt Message
	Steps  []Step
	// Links are the other open form steps next to the form of one step.
	Links    []Step
	Buttons  []Step
	Login    users.Login
	Telegram TelegramWidget
	Tokens   TokenTable
	// TokenForm is the form of a refused POST /tokens. It holds no secret.
	TokenForm TokenForm
	// NewToken is set only on PageTokenCreated.
	NewToken *tokens.Secret
	// Recovery shows the "Forgot password" link.
	Recovery bool
	// ResetToken goes to the hidden field of the new password form, never to a URL.
	ResetToken recovery.Token
	// Invite goes to the hidden field of the invite form, never to a URL.
	Invite invites.Token
	// Script loads passkey.js. The caller MUST open script-src and connect-src for it in the CSP.
	Script bool
	// Enrollment is set only on PageTOTPEnroll.
	Enrollment *Enrollment
	// RecoveryCodes is set only on PageRecoveryCodes.
	RecoveryCodes []totp.RecoveryCode
}

// Step is one way to pass a login step, as a page shows it. A Script step is a button that runs
// a WebAuthn ceremony in passkey.js; any other button posts to Path.
type Step struct {
	Path   string
	Label  string
	Icon   Icon
	Script bool
}

// TelegramWidget is the data of the Telegram Login Widget on a page. The zero value shows no widget.
type TelegramWidget struct {
	BotName telegram.BotName
	AuthURL string
}

// Enrollment is the secret of a TOTP enrollment. The handler MUST set Cache-Control: no-store.
type Enrollment struct {
	Secret totp.Secret
	QR     QRImage
}
