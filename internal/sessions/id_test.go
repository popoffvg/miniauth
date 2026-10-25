package sessions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestIDPrintsRedacted(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	raw := id.Bytes()
	encoded := hex.EncodeToString(raw[:])
	printed := []string{
		fmt.Sprint(id),
		fmt.Sprintf("%v", id),
		fmt.Sprintf("%s", id),
		fmt.Sprintf("%#v", id),
		fmt.Sprintf("%x", id),
		fmt.Sprintf("%X", id),
		id.String(),
		id.GoString(),
	}
	for _, text := range printed {
		if text != "redacted" {
			t.Fatalf("print = %q, want redacted", text)
		}
		if strings.Contains(text, encoded) || strings.Contains(text, id.CookieValue()) {
			t.Fatal("session id leaked in a print")
		}
	}

	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	logger.Info("session", "id", id)
	if strings.Contains(logs.String(), id.CookieValue()) || strings.Contains(logs.String(), encoded) {
		t.Fatal("session id leaked in a log")
	}
	if !strings.Contains(logs.String(), "redacted") {
		t.Fatal("log did not redact the session id")
	}
}

func TestIDMatchesItsHash(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if !id.Matches(id.Hash()) {
		t.Fatal("id does not match its hash")
	}
	other, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if id.Matches(other.Hash()) {
		t.Fatal("id matched another hash")
	}
	sum := id.Hash()
	body := id.Bytes()
	if bytes.Equal(sum[:], body[:]) {
		t.Fatal("hash equals the id")
	}
	want := sha256.Sum256(body[:])
	if sum != Hash(want) {
		t.Fatal("hash is not SHA-256")
	}
	parsed, err := ParseID(id.CookieValue())
	if err != nil {
		t.Fatal(err)
	}
	if parsed != id {
		t.Fatal("ParseID did not return the id")
	}
	_, err = ParseID("not-a-session-id")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("ParseID() error = %v, want ErrNotFound", err)
	}
	_, err = ParseID("secret-value")
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatal("ParseID error contains the value")
	}
}
