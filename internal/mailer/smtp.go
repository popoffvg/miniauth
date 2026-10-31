package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/popoffvg/miniauth/internal/recovery"
)

// ErrNoStartTLS means the relay does not offer STARTTLS. No mail is sent in clear text.
var ErrNoStartTLS = errors.New("mailer: SMTP relay does not offer STARTTLS")

// SMTPMailer sends each mail through one new connection to the relay.
type SMTPMailer struct {
	settings SMTPSettings
	// tlsConfig is nil in production, which verifies the relay against the system roots.
	tlsConfig *tls.Config
	now       func() time.Time
}

// NewSMTPMailer returns a mailer for settings.
func NewSMTPMailer(settings SMTPSettings) *SMTPMailer {
	return &SMTPMailer{settings: settings, now: time.Now}
}

var _ recovery.Mailer = (*SMTPMailer)(nil)

// Send dials the relay, requires STARTTLS, authenticates when a user is set, and sends one mail.
func (m *SMTPMailer) Send(ctx context.Context, mail recovery.Mail) error {
	host := m.settings.Host.String()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", m.settings.Addr())
	if err != nil {
		return fmt.Errorf("mailer: dial: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: greeting: %w", err)
	}
	defer func() { _ = client.Close() }()
	if err := m.deliver(client, host, mail); err != nil {
		return err
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("mailer: quit: %w", err)
	}
	return nil
}

func (m *SMTPMailer) deliver(client *smtp.Client, host string, mail recovery.Mail) error {
	if err := client.Hello("localhost"); err != nil {
		return fmt.Errorf("mailer: hello: %w", err)
	}
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return ErrNoStartTLS
	}
	config := m.tlsConfig
	if config == nil {
		config = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	config = config.Clone()
	config.ServerName = host
	if err := client.StartTLS(config); err != nil {
		return fmt.Errorf("mailer: starttls: %w", err)
	}
	if user := m.settings.User.String(); user != "" {
		// PlainAuth refuses to send the password unless the connection is TLS.
		auth := smtp.PlainAuth("", user, m.settings.Password.raw, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mailer: auth: %w", err)
		}
	}
	if err := client.Mail(m.settings.From.String()); err != nil {
		return fmt.Errorf("mailer: sender: %w", err)
	}
	if err := client.Rcpt(mail.To.String()); err != nil {
		return fmt.Errorf("mailer: recipient: %w", err)
	}
	body, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: data: %w", err)
	}
	if _, err := body.Write(m.message(mail)); err != nil {
		_ = body.Close()
		return fmt.Errorf("mailer: data: %w", err)
	}
	if err := body.Close(); err != nil {
		return fmt.Errorf("mailer: data: %w", err)
	}
	return nil
}

// message is the RFC 5322 text. The To address is a login, and a login has no line break.
func (m *SMTPMailer) message(mail recovery.Mail) []byte {
	var b bytes.Buffer
	header := func(name, value string) {
		b.WriteString(name + ": " + value + "\r\n")
	}
	header("From", m.settings.From.String())
	header("To", mail.To.String())
	header("Subject", mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", " ", "\n", " ").Replace(string(mail.Subject))))
	header("Date", m.now().UTC().Format(time.RFC1123Z))
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(string(mail.Body), "\n", "\r\n"))
	return b.Bytes()
}
