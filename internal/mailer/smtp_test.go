package mailer

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/recovery"
	"github.com/popoffvg/miniauth/internal/users"
)

// relay is a one-connection SMTP server. offerTLS decides whether EHLO lists STARTTLS.
type relay struct {
	ctx      context.Context
	ln       net.Listener
	tls      *tls.Config
	offerTLS bool

	mu       sync.Mutex
	commands []string
	data     string
	tlsUsed  bool
	done     chan struct{}
}

func startRelay(t *testing.T, offerTLS bool) (*relay, *x509.CertPool) {
	t.Helper()
	cert, pool := selfSigned(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	r := &relay{
		ctx:      t.Context(),
		ln:       ln,
		tls:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		offerTLS: offerTLS,
		done:     make(chan struct{}),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go r.serve()
	return r, pool
}

func (r *relay) serve() {
	defer close(r.done)
	conn, err := r.ln.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	write := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	write("220 relay.example.test ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		r.mu.Lock()
		r.commands = append(r.commands, line)
		tlsUsed := r.tlsUsed
		r.mu.Unlock()
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO":
			if r.offerTLS && !tlsUsed {
				write("250-relay.example.test")
				write("250 STARTTLS")
				continue
			}
			write("250-relay.example.test")
			write("250 AUTH PLAIN")
		case "STARTTLS":
			write("220 ready")
			secure := tls.Server(conn, r.tls)
			if secure.HandshakeContext(r.ctx) != nil {
				return
			}
			conn = secure
			reader = bufio.NewReader(conn)
			r.mu.Lock()
			r.tlsUsed = true
			r.mu.Unlock()
		case "AUTH":
			write("235 accepted")
		case "MAIL", "RCPT":
			write("250 ok")
		case "DATA":
			write("354 go on")
			var body strings.Builder
			for {
				part, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if part == ".\r\n" {
					break
				}
				body.WriteString(part)
			}
			r.mu.Lock()
			r.data = body.String()
			r.mu.Unlock()
			write("250 queued")
		case "QUIT":
			write("221 bye")
			return
		default:
			write("502 not implemented")
		}
	}
}

func (r *relay) settings(t *testing.T, user, password string) SMTPSettings {
	t.Helper()
	addr, err := netip.ParseAddrPort(r.ln.Addr().String())
	require.NoError(t, err)
	host, err := ParseSMTPHost(addr.Addr().String())
	require.NoError(t, err)
	from, err := ParseSenderAddress("id@example.test")
	require.NoError(t, err)
	smtpUser, err := ParseSMTPUser(user)
	require.NoError(t, err)
	settings, err := NewSMTPSettings(host, SMTPPort(addr.Port()), smtpUser, NewSMTPPassword(password), from)
	require.NoError(t, err)
	return settings
}

func testMail(t *testing.T) recovery.Mail {
	t.Helper()
	to, err := users.ParseEmail("ada@example.test")
	require.NoError(t, err)
	return recovery.Mail{To: to, Subject: "Set a new password", Body: "line one\n.dot line\n"}
}

func TestSMTPMailerSendsOverStartTLS(t *testing.T) {
	r, pool := startRelay(t, true)
	const password = "relay-password-stays-secret"
	m := NewSMTPMailer(r.settings(t, "miniauth", password))
	m.tlsConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

	require.NoError(t, m.Send(t.Context(), testMail(t)))
	<-r.done

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.True(t, r.tlsUsed)
	var auth string
	for _, command := range r.commands {
		if strings.HasPrefix(command, "AUTH PLAIN ") {
			auth = strings.TrimPrefix(command, "AUTH PLAIN ")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(auth)
	require.NoError(t, err)
	assert.Equal(t, "\x00miniauth\x00"+password, string(decoded))
	assert.Contains(t, r.commands, "MAIL FROM:<id@example.test>")
	assert.Contains(t, r.commands, "RCPT TO:<ada@example.test>")
	assert.Contains(t, r.data, "To: ada@example.test\r\n")
	assert.Contains(t, r.data, "Subject: Set a new password\r\n")
	assert.Contains(t, r.data, "\r\nline one\r\n..dot line\r\n")
}

func TestSMTPMailerRefusesARelayWithoutStartTLS(t *testing.T) {
	r, _ := startRelay(t, false)
	m := NewSMTPMailer(r.settings(t, "miniauth", "relay-password"))
	require.ErrorIs(t, m.Send(t.Context(), testMail(t)), ErrNoStartTLS)
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, command := range r.commands {
		assert.NotContains(t, command, "AUTH")
		assert.NotContains(t, command, "MAIL")
	}
}

func TestSMTPPasswordPrintsRedacted(t *testing.T) {
	host, err := ParseSMTPHost("relay.example.test")
	require.NoError(t, err)
	from, err := ParseSenderAddress("id@example.test")
	require.NoError(t, err)
	user, err := ParseSMTPUser("miniauth")
	require.NoError(t, err)
	settings, err := NewSMTPSettings(host, DefaultSMTPPort, user, NewSMTPPassword("relay-password-stays-secret"), from)
	require.NoError(t, err)
	var logs strings.Builder
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("settings", "value", settings)
	printed := fmt.Sprintf("%v %+v %#v", settings, settings, settings.Password) + logs.String()
	assert.NotContains(t, printed, "relay-password-stays-secret")
}

func TestLogMailerWritesTheMail(t *testing.T) {
	var out strings.Builder
	require.NoError(t, NewLogMailer(&out).Send(t.Context(), testMail(t)))
	assert.Contains(t, out.String(), "To: ada@example.test")
	assert.Contains(t, out.String(), "line one")
}

func TestNewSMTPSettingsRequiresUserAndPasswordTogether(t *testing.T) {
	host, err := ParseSMTPHost("relay.example.test")
	require.NoError(t, err)
	from, err := ParseSenderAddress("id@example.test")
	require.NoError(t, err)
	user, err := ParseSMTPUser("miniauth")
	require.NoError(t, err)
	_, err = NewSMTPSettings(host, DefaultSMTPPort, user, SMTPPassword{}, from)
	require.ErrorIs(t, err, ErrSMTPAuth)
	_, err = NewSMTPSettings(host, DefaultSMTPPort, SMTPUser{}, NewSMTPPassword("x"), from)
	require.ErrorIs(t, err, ErrSMTPAuth)
	_, err = NewSMTPSettings(host, DefaultSMTPPort, SMTPUser{}, SMTPPassword{}, from)
	require.NoError(t, err)
	_, err = ParseSenderAddress("Miniauth <id@example.test>")
	require.ErrorIs(t, err, ErrSMTPFrom)
	_, err = ParseSMTPHost("relay.example.test:25")
	require.ErrorIs(t, err, ErrSMTPHost)
	_, err = ParseSMTPPort("0")
	require.ErrorIs(t, err, ErrSMTPPort)
}

// selfSigned returns a certificate for 127.0.0.1 and a pool that trusts it.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay.example.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}
