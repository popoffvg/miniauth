package config

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	envListen   = "MINIAUTH_LISTEN"
	envDatabase = "MINIAUTH_DATABASE_URL"
	envAdmin    = "MINIAUTH_ADMIN_TOKEN_SHA256"
	envCookie   = "MINIAUTH_COOKIE_DOMAIN"
	envPublic   = "MINIAUTH_PUBLIC_URL"

	defaultListen = "127.0.0.1:8080"
)

var (
	errListen          = errors.New("miniauth: MINIAUTH_LISTEN is not a valid address")
	errDatabaseMissing = errors.New("miniauth: MINIAUTH_DATABASE_URL is not set")
	errDatabase        = errors.New("miniauth: MINIAUTH_DATABASE_URL is not a PostgreSQL connection string")
	errAdmin           = errors.New("miniauth: MINIAUTH_ADMIN_TOKEN_SHA256 must be the hex SHA-256 of the admin token")
	errCookie          = errors.New("miniauth: MINIAUTH_COOKIE_DOMAIN is not a valid cookie domain")
	errPublic          = errors.New("miniauth: MINIAUTH_PUBLIC_URL is not an http or https origin")
)

// Config is the process configuration.
// Load validates it before the process serves.
type Config struct {
	Listen     ListenAddr
	Database   DatabaseURL
	AdminToken api.AdminTokenHash
	Cookie     sessions.Domain
	PublicURL  api.PublicURL
	Mail       Mail
}

// LogValue keeps the database URL and the admin token hash out of a log.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("listen", c.Listen.String()),
		slog.String("database", "redacted"),
		slog.String("admin_token", "redacted"),
		slog.String("cookie_domain", c.Cookie.String()),
		slog.String("public_host", c.PublicURL.Host()),
		slog.String("mail", string(c.Mail.Kind)),
		slog.String("smtp_host", c.Mail.SMTP.Host.String()),
	)
}

// ListenAddr is the TCP address the HTTP server binds.
type ListenAddr struct {
	value string
}

// String returns the address for net.Listen.
func (a ListenAddr) String() string {
	return a.value
}

// DatabaseURL is the PostgreSQL connection string.
// It can hold a password. Printing it yields "redacted".
type DatabaseURL struct {
	users.Redacted
	dsn string
}

// DSN returns the connection string for the driver.
// The caller MUST NOT log it or put it in an error.
func (u DatabaseURL) DSN() string {
	return u.dsn
}

// Load reads MINIAUTH_* from getenv and validates every value.
// An error names the variable. It MUST NOT include the value.
// getenv MUST NOT be nil.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		return Config{}, errors.New("miniauth: config has no environment")
	}
	listen, listenErr := parseListen(getenv(envListen))
	database, databaseErr := parseDatabase(getenv(envDatabase))
	admin, adminErr := parseAdmin(getenv(envAdmin))
	cookie, cookieErr := parseCookie(getenv(envCookie))
	public, publicErr := parsePublic(getenv(envPublic))
	mail, mailErr := parseMail(getenv)
	if err := errors.Join(listenErr, databaseErr, adminErr, cookieErr, publicErr, mailErr); err != nil {
		return Config{}, err
	}
	return Config{
		Listen:     listen,
		Database:   database,
		AdminToken: admin,
		Cookie:     cookie,
		PublicURL:  public,
		Mail:       mail,
	}, nil
}

func parseListen(raw string) (ListenAddr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultListen
	}
	_, port, err := net.SplitHostPort(raw)
	if err != nil || !validPort(port) {
		return ListenAddr{}, errListen
	}
	return ListenAddr{value: raw}, nil
}

func validPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535
}

func parseDatabase(raw string) (DatabaseURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DatabaseURL{}, errDatabaseMissing
	}
	// The driver error can contain the connection string. Do not wrap it.
	if _, err := pgxpool.ParseConfig(raw); err != nil {
		return DatabaseURL{}, errDatabase
	}
	return DatabaseURL{dsn: raw}, nil
}

func parseAdmin(raw string) (api.AdminTokenHash, error) {
	hash, err := api.ParseAdminTokenHash(raw)
	if err != nil {
		return api.AdminTokenHash{}, errAdmin
	}
	return hash, nil
}

func parseCookie(raw string) (sessions.Domain, error) {
	domain, err := sessions.ParseDomain(raw)
	if err != nil {
		return sessions.Domain{}, errCookie
	}
	return domain, nil
}

func parsePublic(raw string) (api.PublicURL, error) {
	public, err := api.ParsePublicURL(raw)
	if err != nil {
		return api.PublicURL{}, errPublic
	}
	return public, nil
}
