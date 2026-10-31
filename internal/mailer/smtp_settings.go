package mailer

import (
	"errors"
	"net"
	"net/mail"
	"strconv"
	"strings"

	"github.com/popoffvg/miniauth/internal/users"
)

// DefaultSMTPPort is the mail submission port with STARTTLS.
const DefaultSMTPPort = 587

var (
	// ErrSMTPHost means the SMTP host is not a host name or an IP address.
	ErrSMTPHost = errors.New("mailer: SMTP host is not valid")
	// ErrSMTPPort means the SMTP port is not 1 to 65535.
	ErrSMTPPort = errors.New("mailer: SMTP port is not valid")
	// ErrSMTPFrom means the sender is not one bare address.
	ErrSMTPFrom = errors.New("mailer: SMTP sender is not a mail address")
	// ErrSMTPAuth means only one of the SMTP user and the SMTP password is set.
	ErrSMTPAuth = errors.New("mailer: SMTP user and password must be set together")
	// ErrSMTPUser means the SMTP user has a line break.
	ErrSMTPUser = errors.New("mailer: SMTP user is not valid")
)

// SMTPHost is the relay host name. It is also the TLS server name.
type SMTPHost struct {
	value string
}

// ParseSMTPHost refuses an empty value, a port, and a line break.
func ParseSMTPHost(raw string) (SMTPHost, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, ":/ \r\n") {
		return SMTPHost{}, ErrSMTPHost
	}
	return SMTPHost{value: raw}, nil
}

func (h SMTPHost) String() string {
	return h.value
}

// SMTPPort is the relay TCP port.
type SMTPPort uint16

// ParseSMTPPort reads a decimal port. An empty value is DefaultSMTPPort.
func ParseSMTPPort(raw string) (SMTPPort, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultSMTPPort, nil
	}
	n, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || n == 0 {
		return 0, ErrSMTPPort
	}
	return SMTPPort(n), nil
}

func (p SMTPPort) String() string {
	return strconv.FormatUint(uint64(p), 10)
}

// SMTPUser is the relay login. It is not a secret.
type SMTPUser struct {
	value string
}

// ParseSMTPUser refuses a line break. An empty value means no authentication.
func ParseSMTPUser(raw string) (SMTPUser, error) {
	if strings.ContainsAny(raw, "\r\n") {
		return SMTPUser{}, ErrSMTPUser
	}
	return SMTPUser{value: raw}, nil
}

func (u SMTPUser) String() string {
	return u.value
}

// SMTPPassword is the relay password. Printing it yields "redacted".
type SMTPPassword struct {
	users.Redacted
	raw string
}

// NewSMTPPassword wraps raw. An empty value means no authentication.
func NewSMTPPassword(raw string) SMTPPassword {
	return SMTPPassword{raw: raw}
}

// SenderAddress is the From address of every mail.
type SenderAddress struct {
	value string
}

// ParseSenderAddress accepts one bare address such as "id@example.test".
func ParseSenderAddress(raw string) (SenderAddress, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := mail.ParseAddress(raw)
	if err != nil || parsed.Name != "" || parsed.Address != raw {
		return SenderAddress{}, ErrSMTPFrom
	}
	return SenderAddress{value: raw}, nil
}

func (a SenderAddress) String() string {
	return a.value
}

// SMTPSettings is the relay configuration.
type SMTPSettings struct {
	Host     SMTPHost
	Port     SMTPPort
	User     SMTPUser
	Password SMTPPassword
	From     SenderAddress
}

// NewSMTPSettings checks the values together. user and password are both set or both empty.
func NewSMTPSettings(host SMTPHost, port SMTPPort, user SMTPUser, password SMTPPassword, from SenderAddress) (SMTPSettings, error) {
	if host == (SMTPHost{}) {
		return SMTPSettings{}, ErrSMTPHost
	}
	if port == 0 {
		return SMTPSettings{}, ErrSMTPPort
	}
	if from == (SenderAddress{}) {
		return SMTPSettings{}, ErrSMTPFrom
	}
	if (user.value == "") != (password.raw == "") {
		return SMTPSettings{}, ErrSMTPAuth
	}
	return SMTPSettings{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		From:     from,
	}, nil
}

// Addr is host:port for a dial.
func (s SMTPSettings) Addr() string {
	return net.JoinHostPort(s.Host.value, s.Port.String())
}
