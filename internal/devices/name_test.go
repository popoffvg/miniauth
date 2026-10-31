package devices

import (
	"strings"
	"testing"
)

func TestNameFromUserAgent(t *testing.T) {
	tests := []struct {
		userAgent string
		want      string
	}{
		{userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0", want: "Firefox on macOS"},
		{userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36", want: "Chrome on Windows"},
		{userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0", want: "Edge on Windows"},
		{userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15", want: "Safari on macOS"},
		{userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1", want: "Chrome on iOS"},
		{userAgent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36", want: "Chrome on Android"},
		{userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", want: "Firefox on Linux"},
		{userAgent: "curl/8.10.1", want: "curl on unknown system"},
		{userAgent: "", want: "Browser on unknown system"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := NameFromUserAgent(tt.userAgent).String(); got != tt.want {
				t.Fatalf("name = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNameFromUserAgentKeepsNoAgentText(t *testing.T) {
	agent := "Mozilla/5.0 " + strings.Repeat("secret-marker ", 500) + "Firefox/131.0"
	got := NameFromUserAgent(agent).String()
	if len(got) > MaxNameLength {
		t.Fatalf("name length = %d", len(got))
	}
	if strings.Contains(got, "secret-marker") {
		t.Fatal("name kept User-Agent text")
	}
}
