package api

import (
	"io/fs"
	"net/http"

	"github.com/popoffvg/miniauth/internal/views"
)

// appCSSPath is the one stylesheet of every page.
const appCSSPath = views.StylesheetPath

var (
	serveAppCSS        = serveAsset("assets/app.css", "text/css; charset=utf-8")
	servePasskeyScript = serveAsset("assets/passkey.js", "text/javascript; charset=utf-8")
)

// serveAsset answers one file of views.Assets. The files are embedded, so a read error is a build fault.
func serveAsset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := fs.ReadFile(views.Assets, name)
		if err != nil {
			loggerFrom(r.Context()).ErrorContext(r.Context(), "miniauth: read asset", "name", name, "err", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
