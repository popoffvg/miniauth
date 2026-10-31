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

const (
	// firstFactors identify the user. Two of them count as one factor.
	firstFactors = Factors(FactorPassword) | Factors(FactorGoogle) | Factors(FactorTelegram)
	// secondFactors count only after a first factor of a user with NeedsSecond.
	secondFactors = Factors(FactorTOTP) | Factors(FactorRecovery)
	allFactors    = firstFactors | secondFactors | Factors(FactorPasskey)
)

// known reports whether f is exactly one factor of this package.
func (f Factor) known() bool {
	return f != 0 && f&(f-1) == 0 && Factors(f)&allFactors != 0
}

// With returns the set plus f.
func (s Factors) With(f Factor) Factors {
	return s | Factors(f)
}

// Has reports whether f is in the set.
func (s Factors) Has(f Factor) bool {
	return s&Factors(f) != 0
}
