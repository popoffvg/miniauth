package mailer

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/popoffvg/miniauth/internal/recovery"
)

// LogMailer writes each mail, link included, to a writer instead of sending it.
// It is for local work only: the reset link in the output is a live secret.
type LogMailer struct {
	mu  sync.Mutex
	out io.Writer
}

// NewLogMailer returns a mailer that writes to out.
func NewLogMailer(out io.Writer) *LogMailer {
	return &LogMailer{out: out}
}

var _ recovery.Mailer = (*LogMailer)(nil)

// Send writes the address, the subject, and the body.
func (m *LogMailer) Send(_ context.Context, mail recovery.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := fmt.Fprintf(m.out, "miniauth: mail not sent (MINIAUTH_MAIL=log)\nTo: %s\nSubject: %s\n\n%s\n", mail.To, mail.Subject, mail.Body); err != nil {
		return fmt.Errorf("mailer: log: %w", err)
	}
	return nil
}
