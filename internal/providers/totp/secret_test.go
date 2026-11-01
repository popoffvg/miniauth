package totp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/popoffvg/miniauth/internal/users"
)

// rfcSecret is the SHA-1 key of the RFC 6238 test vectors.
func rfcSecret() Secret {
	var s Secret
	copy(s.raw[:], "12345678901234567890")
	return s
}

func TestCodeAtMatchesRFC6238(t *testing.T) {
	// The RFC lists 8 digits. A 6-digit code is the last 6 of them.
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, v := range vectors {
		got := rfcSecret().codeAt(StepAt(time.Unix(v.unix, 0)))
		if got.digits != v.want {
			t.Errorf("code at %d = %s, want %s", v.unix, got.digits, v.want)
		}
	}
}

func TestMatchAcceptsOneStepOfSkewOnce(t *testing.T) {
	secret := rfcSecret()
	now := time.Unix(1111111109, 0)
	current := StepAt(now)
	tests := []struct {
		name  string
		step  TimeStep
		after TimeStep
		ok    bool
	}{
		{name: "current step", step: current, ok: true},
		{name: "one step before", step: current - 1, ok: true},
		{name: "one step after", step: current + 1, ok: true},
		{name: "two steps before", step: current - 2},
		{name: "two steps after", step: current + 2},
		{name: "step already used", step: current, after: current},
		{name: "older than the used step", step: current - 1, after: current},
		{name: "later than the used step", step: current + 1, after: current, ok: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := secret.Match(secret.codeAt(tt.step), now, tt.after)
			if ok != tt.ok {
				t.Fatalf("Match() ok = %t, want %t", ok, tt.ok)
			}
			if ok && got != tt.step {
				t.Fatalf("Match() step = %d, want %d", got, tt.step)
			}
		})
	}
}

func TestParseCode(t *testing.T) {
	for _, raw := range []string{"123456", " 123 456 "} {
		code, err := ParseCode(raw)
		if err != nil || code.digits != "123456" {
			t.Fatalf("ParseCode(%q) = %q, %v", raw, code.digits, err)
		}
	}
	for _, raw := range []string{"", "12345", "1234567", "12345a", "１２３４５６"} {
		if _, err := ParseCode(raw); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("ParseCode(%q) error = %v", raw, err)
		}
	}
}

func TestKeyURI(t *testing.T) {
	login, err := users.ParseLogin("ada@example.test")
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse(rfcSecret().KeyURI(login).Reveal())
	if err != nil {
		t.Fatal(err)
	}
	if uri.Scheme != "otpauth" || uri.Host != "totp" || uri.Path != "/miniauth:ada@example.test" {
		t.Fatalf("URI = %s", uri)
	}
	q := uri.Query()
	if q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("issuer") != "miniauth" ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Fatalf("URI query = %v", q)
	}
}

func TestSecretsPrintRedacted(t *testing.T) {
	secret := rfcSecret()
	code := secret.codeAt(1)
	login, err := users.ParseLogin("ada")
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	recovery, err := ParseRecoveryCode("abcd-efgh-ijkl-mnop")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{secret, code, secret.KeyURI(login), key, recovery} {
		for _, verb := range []string{"%v", "%s", "%+v", "%#v", "%x"} {
			if got := fmt.Sprintf(verb, value); got != "redacted" {
				t.Fatalf("%s of %T = %q", verb, value, got)
			}
		}
	}
}

func TestKeySealsForOneUser(t *testing.T) {
	key := testKey(t)
	owner, other := users.NewID(), users.NewID()
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := key.seal(secret, owner)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), string(secret.raw[:])) {
		t.Fatal("sealed secret holds the clear secret")
	}
	opened, err := key.open(sealed, owner)
	if err != nil {
		t.Fatal(err)
	}
	if opened.raw != secret.raw {
		t.Fatal("open returned another secret")
	}
	if _, err := key.open(sealed, other); err == nil {
		t.Fatal("a sealed secret opened for another user")
	}
	if _, err := testKey(t).open(sealed, owner); err == nil {
		t.Fatal("a sealed secret opened with another key")
	}
	if _, err := (Key{}).seal(secret, owner); !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("seal without a key error = %v", err)
	}
}

func TestParseKey(t *testing.T) {
	if _, err := ParseKey(base64.StdEncoding.EncodeToString(make([]byte, 16))); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("16-byte key error = %v", err)
	}
	if _, err := ParseKey("not base64"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad base64 error = %v", err)
	}
	if !testKey(t).Set() {
		t.Fatal("parsed key is not set")
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := newRecoveryCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("got %d codes, want %d", len(codes), RecoveryCodeCount)
	}
	seen := map[RecoveryHash]bool{}
	for _, code := range codes {
		if seen[code.Hash()] {
			t.Fatal("two recovery codes are equal")
		}
		seen[code.Hash()] = true
		parsed, err := ParseRecoveryCode(" " + strings.ToUpper(code.Reveal()) + " ")
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Hash() != code.Hash() {
			t.Fatal("a parsed code has another hash")
		}
	}
	for _, raw := range []string{"", "abcd-efgh-ijkl", "abcd-efgh-ijkl-mno1", "abcd-efgh-ijkl-mnopq"} {
		if _, err := ParseRecoveryCode(raw); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("ParseRecoveryCode(%q) error = %v", raw, err)
		}
	}
}

func testKey(t *testing.T) Key {
	t.Helper()
	raw := make([]byte, keySize)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	key, err := ParseKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
