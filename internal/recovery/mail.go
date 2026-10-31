package recovery

import (
	"context"
	"fmt"

	"github.com/popoffvg/miniauth/internal/users"
)

// MailSubject is the subject line of one mail. It has no line break.
type MailSubject string

// MailBody is the plain-text body of one mail.
type MailBody string

// Mail is one plain-text message to one address.
type Mail struct {
	To      users.Email
	Subject MailSubject
	Body    MailBody
}

// Mailer sends one mail. Send MUST return an error when the mail is not handed over.
type Mailer interface {
	Send(ctx context.Context, mail Mail) error
}

// Links builds the absolute URLs that a mail names.
type Links interface {
	ResetLink(token Token) string
	TokensPage() string
}

func linkMail(to users.Email, link string) Mail {
	return Mail{
		To:      to,
		Subject: "Set a new password",
		Body: MailBody(fmt.Sprintf(
			"Someone asked to set a new password for the account %s.\n\n"+
				"Open this link to set a new password:\n%s\n\n"+
				"The link works once and expires in %d minutes.\n"+
				"If you did not ask for it, ignore this mail. Your password stays the same.\n",
			to, link, int(LinkLifetime.Minutes()),
		)),
	}
}

func changedMail(to users.Email, tokensPage string) Mail {
	return Mail{
		To:      to,
		Subject: "Your password was changed",
		Body: MailBody(fmt.Sprintf(
			"The password of the account %s was changed through a recovery link.\n\n"+
				"Every browser session of the account was signed out.\n"+
				"Personal access tokens stay valid. Review or revoke them on %s\n\n"+
				"If you did not change the password, recover the account again and revoke your tokens.\n",
			to, tokensPage,
		)),
	}
}
