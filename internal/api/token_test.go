package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAdminTokenHash(t *testing.T) {
	sum := sha256.Sum256([]byte("bootstrap-token"))
	encoded := hex.EncodeToString(sum[:])
	hash, err := ParseAdminTokenHash(strings.ToUpper(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !hash.Matches(BearerToken{raw: "bootstrap-token"}) {
		t.Fatal("hash does not match the token")
	}
	if hash.Matches(BearerToken{raw: "other-token"}) {
		t.Fatal("hash matches a different token")
	}
	for _, bad := range []string{"", "abcd", encoded + "aa", "zz" + encoded[2:]} {
		if _, err := ParseAdminTokenHash(bad); err == nil {
			t.Fatalf("ParseAdminTokenHash(%q) succeeded", bad)
		}
	}
}

func TestRequireAdmin(t *testing.T) {
	h := newHarness(t, &memRepo{})
	called := false
	handler := h.router.requireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", nil)
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next handler ran without a token")
	}
	assertProblem(t, rec, http.StatusUnauthorized)
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("WWW-Authenticate = %q", rec.Header().Get("WWW-Authenticate"))
	}

	called = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	handler.ServeHTTP(rec, req)
	if called {
		t.Fatal("next handler ran with a wrong token")
	}
	assertProblem(t, rec, http.StatusUnauthorized)
	assertNoSecret(t, rec.Body.String(), h.token, "wrong-token")

	called = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusNoContent {
		t.Fatalf("called = %v, status = %d", called, rec.Code)
	}
	assertNoSecret(t, rec.Body.String(), h.token)
}

func TestBearerTokenPrintsRedacted(t *testing.T) {
	token := BearerToken{raw: "bootstrap-token"}
	printed := []string{
		fmt.Sprint(token),
		fmt.Sprintf("%v", token),
		fmt.Sprintf("%s", token),
		fmt.Sprintf("%#v", token),
		fmt.Sprintf("%x", token),
		token.String(),
		token.GoString(),
	}
	for _, text := range printed {
		if text != "redacted" || strings.Contains(text, "bootstrap") {
			t.Fatalf("print = %q, want redacted", text)
		}
	}
}
