package api

import (
	"net/http"
	"time"
)

// hostCookie is a cookie of the login host only.
// The __Host- prefix of name requires Secure, Path=/, and no Domain, so a subdomain cannot set it.
func hostCookie(name, value string, ttl time.Duration, now time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl / time.Second),
		Expires:  now.UTC().Add(ttl),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// expiredHostCookie deletes the host cookie name.
func expiredHostCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}
