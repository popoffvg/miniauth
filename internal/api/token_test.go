package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
