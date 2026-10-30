package sessions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		{name: "recovery", factors: loginflow.Factors(loginflow.FactorRecovery), want: "recovery"},
		{name: "passkey", factors: loginflow.Factors(loginflow.FactorPasskey), want: "passkey"},
		{name: "google", factors: loginflow.Factors(loginflow.FactorGoogle), want: "google"},
		{name: "telegram", factors: loginflow.Factors(loginflow.FactorTelegram), want: "telegram"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MethodFromFactors(tt.factors).String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMethodFromFactorsKeepsAFixedOrder(t *testing.T) {
	factors := loginflow.Factors(loginflow.FactorTelegram | loginflow.FactorGoogle | loginflow.FactorPasskey | loginflow.FactorRecovery | loginflow.FactorTOTP | loginflow.FactorPassword)
	require.Equal(t, "password,totp,recovery,passkey,google,telegram", MethodFromFactors(factors).String())
}
