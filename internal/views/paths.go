package views

// The page paths that a page links or posts to. The api package serves each one.
const (
	TokensPath         = "/tokens"
	ConsentsPath       = TokensPath + "/consents"
	OAuthAuthorizePath = "/oauth/authorize"
	SecurityPath       = "/sessions"
	AccessPath         = "/access"
	UsersPath          = "/users"
	GroupsPath         = "/groups"
	PasskeysPath       = "/passkeys"
	PasskeyNewPath     = PasskeysPath + "/new"
	TOTPEnrollPath     = "/sessions/totp/enroll"
	TOTPConfirmPath    = "/sessions/totp/confirm"
	TOTPDisablePath    = "/sessions/totp/disable"
	LinkPath           = "/link"
)
