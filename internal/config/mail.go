package config

import (
	"errors"
	"strings"

	"github.com/popoffvg/miniauth/internal/mailer"
)

const (
	envMail         = "MINIAUTH_MAIL"
	envSMTPHost     = "MINIAUTH_SMTP_HOST"
	envSMTPPort     = "MINIAUTH_SMTP_PORT"
	envSMTPUser     = "MINIAUTH_SMTP_USER"
	envSMTPPassword = "MINIAUTH_SMTP_PASSWORD" // #nosec G101 -- the variable name, not a password.
	envSMTPFrom     = "MINIAUTH_SMTP_FROM"

	mailLogValue = "log"
)

var (
	errMail         = errors.New("miniauth: MINIAUTH_MAIL must be empty or log")
	errMailBoth     = errors.New("miniauth: set MINIAUTH_MAIL=log or MINIAUTH_SMTP_HOST, not both")
	errSMTPHost     = errors.New("miniauth: MINIAUTH_SMTP_HOST is not a host name")
	errSMTPPort     = errors.New("miniauth: MINIAUTH_SMTP_PORT is not a port")
	errSMTPUser     = errors.New("miniauth: MINIAUTH_SMTP_USER is not valid")
	errSMTPFrom     = errors.New("miniauth: MINIAUTH_SMTP_FROM is not one bare mail address")
	errSMTPAuth     = errors.New("miniauth: set MINIAUTH_SMTP_USER and MINIAUTH_SMTP_PASSWORD together")
	errSMTPWithout  = errors.New("miniauth: MINIAUTH_SMTP_* is set without MINIAUTH_SMTP_HOST")
	errSMTPSettings = errors.New("miniauth: SMTP settings are not valid")
)

// MailKind is how recovery mail goes out.
type MailKind string

const (
	// MailOff sends no mail. The recovery routes answer 503.
	MailOff MailKind = "off"
	// MailLog writes each mail to the process output. It is for local work only.
	MailLog MailKind = "log"
	// MailSMTP sends through the relay in SMTP.
	MailSMTP MailKind = "smtp"
)

// Mail is the mail configuration. SMTP is set only for MailSMTP.
type Mail struct {
	Kind MailKind
	SMTP mailer.SMTPSettings
}

// parseMail picks the log writer only when MINIAUTH_MAIL=log is set explicitly.
func parseMail(getenv func(string) string) (Mail, error) {
	mode := strings.TrimSpace(getenv(envMail))
	host := strings.TrimSpace(getenv(envSMTPHost))
	if mode != "" && mode != mailLogValue {
		return Mail{}, errMail
	}
	if mode == mailLogValue && host != "" {
		return Mail{}, errMailBoth
	}
	if mode == mailLogValue {
		return Mail{Kind: MailLog}, nil
	}
	if host == "" {
		for _, key := range []string{envSMTPPort, envSMTPUser, envSMTPPassword, envSMTPFrom} {
			if getenv(key) != "" {
				return Mail{}, errSMTPWithout
			}
		}
		return Mail{Kind: MailOff}, nil
	}
	settings, err := parseSMTP(getenv)
	if err != nil {
		return Mail{}, err
	}
	return Mail{Kind: MailSMTP, SMTP: settings}, nil
}

func parseSMTP(getenv func(string) string) (mailer.SMTPSettings, error) {
	host, hostErr := mailer.ParseSMTPHost(getenv(envSMTPHost))
	port, portErr := mailer.ParseSMTPPort(getenv(envSMTPPort))
	user, userErr := mailer.ParseSMTPUser(getenv(envSMTPUser))
	from, fromErr := mailer.ParseSenderAddress(getenv(envSMTPFrom))
	if err := errors.Join(
		named(hostErr, errSMTPHost),
		named(portErr, errSMTPPort),
		named(userErr, errSMTPUser),
		named(fromErr, errSMTPFrom),
	); err != nil {
		return mailer.SMTPSettings{}, err
	}
	settings, err := mailer.NewSMTPSettings(host, port, user, mailer.NewSMTPPassword(getenv(envSMTPPassword)), from)
	if errors.Is(err, mailer.ErrSMTPAuth) {
		return mailer.SMTPSettings{}, errSMTPAuth
	}
	if err != nil {
		return mailer.SMTPSettings{}, errSMTPSettings
	}
	return settings, nil
}

// named replaces err with the error that names the variable. The value is never in it.
func named(err, name error) error {
	if err != nil {
		return name
	}
	return nil
}
