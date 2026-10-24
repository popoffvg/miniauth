package main

import (
	"strings"
	"testing"
)

func TestRejectArgsDoesNotEchoTheArguments(t *testing.T) {
	const secret = "not-a-real-admin-token"
	err := rejectArgs([]string{"user", "create", "--login", "ada", secret})
	if err == nil {
		t.Fatal("arguments were accepted")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "ada") || strings.Contains(err.Error(), "create") {
		t.Fatal("error contains an argument")
	}
	if err := rejectArgs(nil); err != nil {
		t.Fatal(err)
	}
}
