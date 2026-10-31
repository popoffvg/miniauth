package config

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/popoffvg/miniauth/internal/api"
	"github.com/popoffvg/miniauth/internal/googlestep"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/telegramstep"
	"github.com/popoffvg/miniauth/internal/totpstep"
	"github.com/popoffvg/miniauth/internal/users"
)

const (
	envListen        = "MINIAUTH_LISTEN"
	envDatabase      = "MINIAUTH_DATABASE_URL"
	envAdmin         = "MINIAUTH_ADMIN_TOKEN_SHA256"
	envCookie        = "MINIAUTH_COOKIE_DOMAIN"
	envPublic        = "MINIAUTH_PUBLIC_URL"
	envGoogleID      = "MINIAUTH_GOOGLE_CLIENT_ID"
	envGoogleSecret  = "MINIAUTH_GOOGLE_CLIENT_SECRET" // #nosec G101 -- the name of the variable, not a secret.
	envTelegramBot   = "MINIAUTH_TELEGRAM_BOT_NAME"
	envTelegramToken = "MINIAUTH_TELEGRAM_BOT_TOKEN" // #nosec G101 -- the name of the variable, not a secret.
	envTOTPKey       = "MINIAUTH_TOTP_KEY"

	defaultListen = "127.0.0.1:8080"
)

var (
	errListen          = errors.New("miniauth: MINIAUTH_LISTEN is not a valid address")
	errDatabaseMissing = errors.New("miniauth: MINIAUTH_DATABASE_URL is not set")
	errDatabase        = errors.New("miniauth: MINIAUTH_DATABASE_URL is not a PostgreSQL connection string")
	errAdmin           = errors.New("miniauth: MINIAUTH_ADMIN_TOKEN_SHA256 must be the hex SHA-256 of the admin token")
	errCookie          = errors.New("miniauth: MINIAUTH_COOKIE_DOMAIN is not a valid cookie domain")
	errPublic          = errors.New("miniauth: MINIAUTH_PUBLIC_URL is not an http or https origin")
	errGoogle          = errors.New("miniauth: MINIAUTH_GOOGLE_CLIENT_ID and MINIAUTH_GOOGLE_CLIENT_SECRET must be set together, with MINIAUTH_PUBLIC_URL")
	errTOTPKey         = errors.New("miniauth: MINIAUTH_TOTP_KEY must be 32 bytes in base64")
	errTelegram        = errors.New("miniauth: MINIAUTH_TELEGRAM_BOT_NAME and MINIAUTH_TELEGRAM_BOT_TOKEN must be set together, with MINIAUTH_PUBLIC_URL; the bot name is 5 to 32 letters, digits, or underscores")
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
	Google     GoogleClient
	Telegram   TelegramBot
	// TOTPKey seals each TOTP secret. Without it, TOTP enrollment is off.
	TOTPKey totpstep.Key
}

// GoogleClient is the OAuth client of the Google step. The zero value turns the step off.
type GoogleClient struct {
	ID     googlestep.ClientID
	Secret googlestep.ClientSecret
}

// Enabled reports whether the Google step is configured.
func (g GoogleClient) Enabled() bool {
	return g.ID != (googlestep.ClientID{})
}

// TelegramBot is the bot of the Telegram step. The zero value turns the step off.
type TelegramBot struct {
	Name  telegramstep.BotName
	Token telegramstep.BotToken
}

// Enabled reports whether the Telegram step is configured.
func (t TelegramBot) Enabled() bool {
	return t.Name != (telegramstep.BotName{})
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
		slog.Bool("google", c.Google.Enabled()),
		slog.Bool("telegram", c.Telegram.Enabled()),
		slog.Bool("totp_key_set", c.TOTPKey.Set()),
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
	google, googleErr := parseGoogle(getenv(envGoogleID), getenv(envGoogleSecret), public)
	telegram, telegramErr := parseTelegram(getenv(envTelegramBot), getenv(envTelegramToken), public)
	totpKey, totpKeyErr := parseTOTPKey(getenv(envTOTPKey))
	if err := errors.Join(listenErr, databaseErr, adminErr, cookieErr, publicErr, mailErr, googleErr, telegramErr, totpKeyErr); err != nil {
		return Config{}, err
	}
	return Config{
		Listen:     listen,
		Database:   database,
		AdminToken: admin,
		Cookie:     cookie,
		PublicURL:  public,
		Mail:       mail,
		Google:     google,
		Telegram:   telegram,
		TOTPKey:    totpKey,
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

// parseGoogle accepts both values or neither. The Google redirect URL is built from the public URL.
func parseGoogle(rawID, rawSecret string, public api.PublicURL) (GoogleClient, error) {
	id := googlestep.ParseClientID(rawID)
	secret := googlestep.ParseClientSecret(rawSecret)
	if id == (googlestep.ClientID{}) && secret.Empty() {
		return GoogleClient{}, nil
	}
	if id == (googlestep.ClientID{}) || secret.Empty() || public.Origin() == "" {
		return GoogleClient{}, errGoogle
	}
	return GoogleClient{ID: id, Secret: secret}, nil
}

// parseTelegram accepts both values or neither. The widget callback URL is built from the public URL.
func parseTelegram(rawName, rawToken string, public api.PublicURL) (TelegramBot, error) {
	name, nameErr := telegramstep.ParseBotName(rawName)
	token := telegramstep.ParseBotToken(rawToken)
	if nameErr != nil {
		return TelegramBot{}, errTelegram
	}
	if name == (telegramstep.BotName{}) && token.Empty() {
		return TelegramBot{}, nil
	}
	if name == (telegramstep.BotName{}) || token.Empty() || public.Origin() == "" {
		return TelegramBot{}, errTelegram
	}
	return TelegramBot{Name: name, Token: token}, nil
}

// parseTOTPKey reads an empty value as no key.
func parseTOTPKey(raw string) (totpstep.Key, error) {
	if strings.TrimSpace(raw) == "" {
		return totpstep.Key{}, nil
	}
	key, err := totpstep.ParseKey(raw)
	if err != nil {
		return totpstep.Key{}, errTOTPKey
	}
	return key, nil
}
