package views

import (
	"strconv"
	"strings"
	"testing"

	"github.com/a-h/templ"

	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/tokens"
)

// A browser counts maxlength in UTF-16 units. A character outside the BMP is two units,
// so a field MUST allow twice the characters that the server allows.
func TestNameFieldsAllowEveryNameTheServerAllows(t *testing.T) {
	tests := []struct {
		name  string
		page  templ.Component
		runes int
	}{
		{name: "token", page: tokenFormCard(TokenForm{}), runes: tokens.MaxNameLengthRunes},
		{name: "passkey", page: passkeyNewPage(Page{}), runes: passkey.MaxNameLengthRunes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body strings.Builder
			if err := tt.page.Render(t.Context(), &body); err != nil {
				t.Fatal(err)
			}
			want := `maxlength="` + strconv.Itoa(2*tt.runes) + `"`
			if !strings.Contains(body.String(), want) {
				t.Fatalf("the name field has no %s", want)
			}
		})
	}
}
