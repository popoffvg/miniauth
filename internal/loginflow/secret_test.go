package loginflow

import (
	"bytes"
	"crypto/sha256"
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
	hash, err := secret.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if !secret.Matches(hash) {
		t.Fatal("secret does not match its hash")
	}
	other, err := NewFlowSecret()
	if err != nil {
		t.Fatal(err)
	}
	if other.Matches(hash) {
		t.Fatal("another secret matched the hash")
	}
	body := secret.Bytes()
	if bytes.Equal(hash.Digest[:], body[:]) {
		t.Fatal("hash equals the secret")
	}
	unsalted := sha256.Sum256(body[:])
	if bytes.Equal(hash.Digest[:], unsalted[:]) {
		t.Fatal("hash equals the unsalted SHA-256 of the secret")
	}
}

func TestFlowSecretSaltChangesHash(t *testing.T) {
	secret, err := NewFlowSecret()
	if err != nil {
		t.Fatal(err)
	}
	first, err := secret.Hash()
	if err != nil {
		t.Fatal(err)
	}
	second, err := secret.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if first.Salt == second.Salt {
		t.Fatal("two hashes share one salt")
	}
	if first.Digest == second.Digest {
		t.Fatal("two salts gave one digest")
	}
	if !secret.Matches(first) || !secret.Matches(second) {
		t.Fatal("secret does not match a salted hash")
	}
	swapped := SecretHash{Salt: second.Salt, Digest: first.Digest}
	if secret.Matches(swapped) {
		t.Fatal("digest matched under another salt")
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
