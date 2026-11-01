package views

import (
	"bytes"
	"context"
	"fmt"

	"github.com/a-h/templ"
)

// PageName names one page that reads a Page.
type PageName string

// The pages that PageOf renders.
const (
	PageLogin       PageName = "login"
	PageSteps       PageName = "steps"
	PageDenied      PageName = "denied"
	PageStepUp      PageName = "step-up"
	PageTokens      PageName = "tokens"
	PageConsent     PageName = "consent"
	PageRecover     PageName = "recover"
	PageRecoverSent PageName = "recover-sent"
	PageReset       PageName = "reset"
	PageResetDone   PageName = "reset-done"
	PageInvite      PageName = "invite"
	// PageAddKey is the form that adds a passkey. It loads passkey.js. The handler MUST set Script in the view.
	PageAddKey PageName = "passkey-new"
	// PageTokenCreated shows the clear token. The handler MUST set Cache-Control: no-store.
	PageTokenCreated PageName = "token-created"
	PageTOTP         PageName = "totp"
	PageRecoveryCode PageName = "recovery-code"
	// PageTOTPEnroll shows the TOTP secret. The handler MUST set Cache-Control: no-store.
	PageTOTPEnroll PageName = "totp-enroll"
	// PageRecoveryCodes shows the clear recovery codes. The handler MUST set Cache-Control: no-store.
	PageRecoveryCodes PageName = "recovery-codes"
)

// pageComponents is the templ component of each PageName.
var pageComponents = map[PageName]func(Page) templ.Component{
	PageLogin:         loginForm,
	PageSteps:         stepChooser,
	PageDenied:        deniedPage,
	PageStepUp:        stepUpForm,
	PageTokens:        tokensPage,
	PageConsent:       consentPage,
	PageRecover:       recoverForm,
	PageRecoverSent:   recoverSentPage,
	PageReset:         resetForm,
	PageResetDone:     resetDonePage,
	PageInvite:        inviteForm,
	PageAddKey:        passkeyNewPage,
	PageTokenCreated:  tokenCreatedPage,
	PageTOTP:          totpForm,
	PageRecoveryCode:  recoveryCodeForm,
	PageTOTPEnroll:    totpEnrollPage,
	PageRecoveryCodes: recoveryCodesPage,
}

// PageOf returns the component of name with view. It is false for a name with no page.
func PageOf(name PageName, view Page) (templ.Component, bool) {
	component, ok := pageComponents[name]
	if !ok {
		return nil, false
	}
	return component(view), true
}

// Render renders page into memory, so a render error leaves no partial body for the caller to send.
func Render(ctx context.Context, page templ.Component) ([]byte, error) {
	var body bytes.Buffer
	if err := page.Render(ctx, &body); err != nil {
		return nil, fmt.Errorf("views: render: %w", err)
	}
	return body.Bytes(), nil
}
