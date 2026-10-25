package sessions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSetCookieAttributes(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	domain, err := ParseDomain(".Example.Test")
	if err != nil {
		t.Fatal(err)
	}
	if domain.String() != ".example.test" {
		t.Fatalf("domain = %q", domain)
	}
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	rec := httptest.NewRecorder()
	SetCookie(rec, id, domain, now)
	cookie := parseSetCookie(t, rec)
	if cookie.Name != CookieName {
		t.Fatalf("name = %s", cookie.Name)
	}
	if !strings.HasPrefix(cookie.Name, "__Secure-") {
		t.Fatal("cookie name has no __Secure- prefix")
	}
	if cookie.Value != id.CookieValue() {
		t.Fatal("cookie value does not match the session id")
	}
	if cookie.Domain != "example.test" {
		t.Fatalf("domain = %q", cookie.Domain)
	}
	if cookie.Path != "/" {
		t.Fatalf("path = %s", cookie.Path)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("flags HttpOnly=%v Secure=%v SameSite=%v", cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}
	const wantMaxAge = 30 * 24 * 60 * 60
	if cookie.MaxAge != wantMaxAge || Lifetime != 30*24*time.Hour {
		t.Fatalf("max-age = %d", cookie.MaxAge)
	}
	if !cookie.Expires.Equal(now.Add(Lifetime)) {
		t.Fatalf("expires = %s", cookie.Expires)
	}
	header := rec.Header().Get("Set-Cookie")
	if !strings.Contains(header, "HttpOnly") || !strings.Contains(header, "Secure") || !strings.Contains(header, "SameSite=Lax") {
		t.Fatalf("header = %s", redactCookie(header, id))
	}
	if strings.Contains(header, "Domain=.example.test") {
		t.Fatal("header kept the leading dot")
	}
}

func TestClearCookieDropsTheParentDomain(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	domain, err := ParseDomain("example.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	ClearCookie(rec, domain)
	cookie := parseSetCookie(t, rec)
	if cookie.Value != "" || cookie.MaxAge >= 0 {
		t.Fatalf("clear value %q max-age %d", cookie.Value, cookie.MaxAge)
	}
	if cookie.Domain != "example.test" || cookie.Path != "/" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("clear cookie does not match the session cookie")
	}
	if strings.Contains(rec.Header().Get("Set-Cookie"), id.CookieValue()) {
		t.Fatal("clear cookie contains a session id")
	}
}

func TestHostOnlyCookieOmitsDomain(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	SetCookie(rec, id, Domain{}, time.Now())
	if strings.Contains(rec.Header().Get("Set-Cookie"), "Domain=") {
		t.Fatal("host-only cookie has a domain")
	}
}

func TestParseDomain(t *testing.T) {
	domain, err := ParseDomain("  ")
	if err != nil || domain.String() != "" {
		t.Fatalf("empty domain = %q, %v", domain, err)
	}
	const secret = "idp_secret_value"
	_, err = ParseDomain(secret)
	if err == nil {
		t.Fatal("ParseDomain accepted a token")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("domain error contains the value")
	}
	for _, raw := range []string{"https://example.test", "example.test/path", "127.0.0.1", ".", "bad domain", "example.test:443"} {
		if _, err := ParseDomain(raw); err == nil {
			t.Fatalf("ParseDomain accepted %q", raw)
		}
	}
}

func TestFromRequest(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logout", nil)
	_, err = FromRequest(req)
	if err == nil {
		t.Fatal("missing cookie was accepted")
	}
	req.AddCookie(&http.Cookie{Name: CookieName, Value: id.CookieValue()})
	got, err := FromRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatal("FromRequest returned another id")
	}
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "%%%"})
	_, err = FromRequest(req)
	if err == nil {
		t.Fatal("malformed cookie was accepted")
	}
}

func parseSetCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	cookie, err := http.ParseSetCookie(rec.Header().Get("Set-Cookie"))
	if err != nil {
		t.Fatal(err)
	}
	return cookie
}

func redactCookie(header string, id ID) string {
	return strings.ReplaceAll(header, id.CookieValue(), "redacted")
}
