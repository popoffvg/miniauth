package views

import "embed"

// Assets holds app.css and passkey.js under assets/.
//
//go:embed assets
var Assets embed.FS

// The paths are where the api package serves Assets. Every page links them.
const (
	StylesheetPath    = "/assets/app.css"
	PasskeyScriptPath = "/assets/passkey.js"
)
