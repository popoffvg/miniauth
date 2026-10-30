package sessions

import (
	"net/http"
	"strings"
	"time"
	"unicode"
)

// CookieName is the session cookie.
// The __Secure- prefix requires the Secure attribute.
const CookieName = "__Secure-id_session"

// Domain is the Domain attribute of the session cookie.
// The zero value is a host-only cookie.
type Domain struct {
	name string
}

// ParseDomain reads the cookie domain from configuration.
// An empty value is a host-only cookie.
// A leading dot is kept in the value. The browser treats it as the parent domain.
// The error MUST NOT contain raw.
func ParseDomain(raw string) (Domain, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "" {
		return Domain{}, nil
	}
	if !validDomain(name) {
		return Domain{}, ErrDomain
	}
	return Domain{name: name}, nil
}

// String returns the configured domain. An empty string means host-only.
func (d Domain) String() string {
	return d.name
}

// SetCookie writes the session cookie.
// The cookie is HttpOnly, Secure, and SameSite=Lax, and it lives for Lifetime.
func SetCookie(w http.ResponseWriter, id ID, domain Domain, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id.CookieValue(),
		Path:     "/",
		Domain:   domain.name,
		MaxAge:   lifetimeSeconds,
		Expires:  now.UTC().Add(Lifetime),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie removes the session cookie.
// Domain and Path match SetCookie, so the browser drops the parent-domain cookie.
func ClearCookie(w http.ResponseWriter, domain Domain) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Domain:   domain.name,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// FromRequest reads the session id from the cookie.
// A missing or malformed cookie is ErrNotFound.
func FromRequest(r *http.Request) (ID, error) {
	ids := IDsFromRequest(r)
	if len(ids) == 0 {
		return ID{}, ErrNotFound
	}
	return ids[0], nil
}

// IDsFromRequest returns every session id in cookie order.
// A browser can send a stale host-only cookie before the parent-domain cookie.
func IDsFromRequest(r *http.Request) []ID {
	if r == nil {
		return nil
	}
	var ids []ID
	for _, cookie := range r.Cookies() {
		if cookie.Name != CookieName {
			continue
		}
		id, err := ParseID(cookie.Value)
		if err != nil {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

const lifetimeSeconds = int(Lifetime / time.Second)

func validDomain(name string) bool {
	if len(name) > 253 {
		return false
	}
	rest := strings.TrimPrefix(name, ".")
	if rest == "" || strings.HasPrefix(rest, ".") || strings.HasSuffix(rest, ".") || strings.Contains(rest, "..") {
		return false
	}
	labels := strings.Split(rest, ".")
	letter := false
	for _, label := range labels {
		if !validLabel(label) {
			return false
		}
		for _, r := range label {
			if unicode.IsLetter(r) {
				letter = true
			}
		}
	}
	return letter
}

func validLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
