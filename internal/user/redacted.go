package user

import (
	"fmt"
	"io"
	"log/slog"
)

// Redacted is embedded in a secret.
// fmt and slog then print "redacted" instead of the secret.
type Redacted struct{}

// String keeps a secret out of fmt.
func (Redacted) String() string { return "redacted" }

// GoString keeps a secret out of %#v.
func (Redacted) GoString() string { return "redacted" }

// Format keeps a secret out of every fmt verb.
func (Redacted) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "redacted")
}

// LogValue keeps a secret out of slog.
func (Redacted) LogValue() slog.Value {
	return slog.StringValue("redacted")
}
