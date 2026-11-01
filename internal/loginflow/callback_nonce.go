package loginflow

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// callbackNonceLabel keeps the nonce apart from any other value that a later change derives from the secret.
const callbackNonceLabel = "miniauth callback nonce"

// CallbackNonce binds an outside callback URL to one flow. It is the HMAC of a label under the flow secret,
// so it shows nothing of the secret, and only the browser with the flow cookie can match it.
type CallbackNonce struct {
	value string
}

// CallbackNonce returns the nonce of the flow of s.
func (s FlowSecret) CallbackNonce() CallbackNonce {
	mac := hmac.New(sha256.New, s.raw[:])
	_, _ = mac.Write([]byte(callbackNonceLabel))
	return CallbackNonce{value: base64.RawURLEncoding.EncodeToString(mac.Sum(nil))}
}

func (n CallbackNonce) String() string {
	return n.value
}

// Matches reports whether raw is the nonce. The comparison is constant time.
func (n CallbackNonce) Matches(raw string) bool {
	return n.value != "" && subtle.ConstantTimeCompare([]byte(n.value), []byte(raw)) == 1
}
