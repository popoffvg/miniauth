package sessions

import (
	"strings"

	"github.com/popoffvg/miniauth/internal/loginflow"
)

// Method is how a session was authenticated.
// The value is safe for a response header.
type Method struct {
	value string
}

// MethodFromFactors names the factors in a fixed order.
// A session with no factor is "session".
func MethodFromFactors(factors loginflow.Factors) Method {
	names := make([]string, 0, 6)
	if factors.Has(loginflow.FactorPassword) {
		names = append(names, "password")
	}
	if factors.Has(loginflow.FactorTOTP) {
		names = append(names, "totp")
	}
	if factors.Has(loginflow.FactorRecovery) {
		names = append(names, "recovery")
	}
	if factors.Has(loginflow.FactorPasskey) {
		names = append(names, "passkey")
	}
	if factors.Has(loginflow.FactorGoogle) {
		names = append(names, "google")
	}
	if factors.Has(loginflow.FactorTelegram) {
		names = append(names, "telegram")
	}
	if len(names) == 0 {
		return Method{value: "session"}
	}
	return Method{value: strings.Join(names, ",")}
}

func (m Method) String() string {
	return m.value
}
