package api

import (
	_ "embed"
	"net/http"
)

// appCSSPath is the one stylesheet of every page.
const appCSSPath = "/assets/app.css"

//go:embed assets/app.css
var appCSS []byte

func serveAppCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(appCSS)
}
