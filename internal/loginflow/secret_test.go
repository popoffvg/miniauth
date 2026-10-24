package loginflow

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestFlowSecretPrintsRedacted(t *testing.T) {
	secret, err := NewFlowSecret()
	if err != nil {
		t.Fatal(err)
	}
	rawBytes := secret.Bytes()
	raw := hex.EncodeToString(rawBytes[:])
	printed := []string{
		fmt.Sprint(secret),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%s", secret),
		fmt.Sprintf("%#v", secret),
		fmt.Sprintf("%x", secret),
		fmt.Sprintf("%X", secret),
		secret.String(),
		secret.GoString(),
	}
	for _, text := range printed {
		if text != "redacted" {
			t.Fatalf("print = %q, want redacted", text)
		}
		if strings.Contains(text, raw) {
			t.Fatalf("secret leaked in %q", text)
		}
	}
}

func TestFlowSecretMatchesItsHash(t *testing.T) {
	secret, err := NewFlowSecret()
	if err != nil {
		t.Fatal(err)
	}
	if !secret.Matches(secret.Hash()) {
		t.Fatal("secret does not match its hash")
	}
	other, err := NewFlowSecret()
	if err != nil {
		t.Fatal(err)
	}
	if secret.Matches(other.Hash()) {
		t.Fatal("secret matched another hash")
	}
	sum := secret.Hash()
	body := secret.Bytes()
	if hex.EncodeToString(sum[:]) == hex.EncodeToString(body[:]) {
		t.Fatal("hash equals the secret")
	}
}

func TestParseFlowID(t *testing.T) {
	id, err := NewFlowID()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFlowID(strings.ToUpper(id.String()))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != id {
		t.Fatalf("ParseFlowID() = %s, want %s", parsed, id)
	}
	if _, err := ParseFlowID("not-a-uuid"); err == nil {
		t.Fatal("ParseFlowID accepted a bad value")
	}
}

func TestNewReturnURL(t *testing.T) {
	got, err := NewReturnURL("https://example.test/back")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "https://example.test/back" {
		t.Fatalf("return URL = %s", got)
	}
	if _, err := NewReturnURL("  "); !errors.Is(err, ErrReturnURL) {
		t.Fatalf("empty return URL error = %v", err)
	}
}
