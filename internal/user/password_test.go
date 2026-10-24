package user

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPasswordPrintsRedacted(t *testing.T) {
	password, err := NewPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	printed := []string{
		fmt.Sprint(password),
		fmt.Sprintf("%v", password),
		fmt.Sprintf("%s", password),
		fmt.Sprintf("%#v", password),
		fmt.Sprintf("%x", password),
		password.String(),
		password.GoString(),
	}
	for _, text := range printed {
		if text != "redacted" {
			t.Fatalf("print = %q, want redacted", text)
		}
		if strings.Contains(text, "horse") {
			t.Fatalf("password leaked in %q", text)
		}
	}
}

func TestHashPasswordMatchesAndHidesThePassword(t *testing.T) {
	password, err := NewPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	first, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if first.Encoded() == second.Encoded() {
		t.Fatal("two hashes share a salt")
	}
	if strings.Contains(first.Encoded(), "horse") || strings.Contains(first.String(), "horse") {
		t.Fatal("password or hash leaked")
	}
	if first.String() != "redacted" || fmt.Sprintf("%#v", first) != "redacted" {
		t.Fatal("hash does not print redacted")
	}
	ok, err := first.Matches(password)
	if err != nil || !ok {
		t.Fatalf("Matches() = %v, %v", ok, err)
	}
	other, err := NewPassword("wrong horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err = first.Matches(other)
	if err != nil || ok {
		t.Fatalf("wrong password Matches() = %v, %v", ok, err)
	}
	parsed, err := ParsePasswordHash(first.Encoded())
	if err != nil {
		t.Fatal(err)
	}
	ok, err = parsed.Matches(password)
	if err != nil || !ok {
		t.Fatalf("parsed Matches() = %v, %v", ok, err)
	}
}

func TestParseLogin(t *testing.T) {
	login, err := ParseLogin("  Ada ")
	if err != nil {
		t.Fatal(err)
	}
	if login.String() != "ada" {
		t.Fatalf("login = %s", login)
	}
	if _, err := ParseLogin("."); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("error = %v", err)
	}
	if _, err := NewPassword(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty password error = %v", err)
	}
}
