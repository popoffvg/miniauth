package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/devices"
)

func TestSetDeviceCookieAttributes(t *testing.T) {
	token, err := devices.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	domain, err := ParseDomain(".example.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	rec := httptest.NewRecorder()
	SetDeviceCookie(rec, token, domain, now)
	cookie := parseSetCookie(t, rec)
	if cookie.Name != "__Secure-id_device" || cookie.Value != token.CookieValue() {
		t.Fatalf("cookie name = %s", cookie.Name)
	}
	if cookie.Domain != "example.test" || cookie.Path != "/" {
		t.Fatalf("domain = %q path = %q", cookie.Domain, cookie.Path)
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("flags HttpOnly=%v Secure=%v SameSite=%v", cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}
	const twoYears = 2 * 365 * 24 * 60 * 60
	if cookie.MaxAge != twoYears || !cookie.Expires.Equal(now.Add(devices.CookieLifetime)) {
		t.Fatalf("max-age = %d expires = %s", cookie.MaxAge, cookie.Expires)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", nil)
	req.AddCookie(&http.Cookie{Name: DeviceCookieName, Value: "%%%"})
	req.AddCookie(&http.Cookie{Name: DeviceCookieName, Value: token.CookieValue()})
	got, ok := DeviceTokenFromRequest(req)
	if !ok || got.Hash() != token.Hash() {
		t.Fatal("DeviceTokenFromRequest did not return the valid cookie")
	}
}
