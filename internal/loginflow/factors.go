package loginflow

// Factor is one way the user proved identity during a login.
type Factor uint16

const (
	// FactorPassword is a password check.
	FactorPassword Factor = 1 << iota
	// FactorTOTP is a time-based one-time code.
	FactorTOTP
	// FactorRecovery is a one-time recovery code. It counts only after NeedsSecond is set.
	FactorRecovery
	// FactorPasskey is a passkey with user verification. It counts as two factors.
	FactorPasskey
	// FactorGoogle is a linked Google account.
	FactorGoogle
	// FactorTelegram is a linked Telegram account.
	FactorTelegram
)

// Factors is the set of factors collected in one flow.
type Factors uint16

// With returns the set plus f.
func (s Factors) With(f Factor) Factors {
	return s | Factors(f)
}

// Has reports whether f is in the set.
func (s Factors) Has(f Factor) bool {
	return s&Factors(f) != 0
}
