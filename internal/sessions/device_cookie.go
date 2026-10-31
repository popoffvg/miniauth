package sessions

import (
	"net/http"
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
)

// DeviceCookieName is the device cookie. Logout keeps it.
const DeviceCookieName = "__Secure-id_device"

const deviceCookieSeconds = int(devices.CookieLifetime / time.Second)

// SetDeviceCookie writes the device cookie with the same Domain as the session cookie.
func SetDeviceCookie(w http.ResponseWriter, token devices.Token, domain Domain, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     DeviceCookieName,
		Value:    token.CookieValue(),
		Path:     "/",
		Domain:   domain.name,
		MaxAge:   deviceCookieSeconds,
		Expires:  now.UTC().Add(devices.CookieLifetime),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// DeviceTokenFromRequest returns the first valid device token in cookie order.
func DeviceTokenFromRequest(r *http.Request) (devices.Token, bool) {
	if r == nil {
		return devices.Token{}, false
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name != DeviceCookieName {
			continue
		}
		token, err := devices.ParseToken(cookie.Value)
		if err == nil {
			return token, true
		}
	}
	return devices.Token{}, false
}
