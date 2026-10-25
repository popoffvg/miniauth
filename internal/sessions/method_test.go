package sessions

import (
	"testing"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

func TestMethodFromFactors(t *testing.T) {
	tests := []struct {
		name    string
		factors loginflow.Factors
		want    string
	}{
		{name: "none", want: "session"},
		{name: "password", factors: loginflow.Factors(loginflow.FactorPassword), want: "password"},
		{
			name:    "password and totp",
			factors: loginflow.Factors(loginflow.FactorTOTP | loginflow.FactorPassword),
			want:    "password,totp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MethodFromFactors(tt.factors).String(); got != tt.want {
				t.Fatalf("method = %s, want %s", got, tt.want)
			}
		})
	}
}
