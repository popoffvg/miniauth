package totp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/popoffvg/miniauth/internal/users"
)

const keySize = 32

// Key is the AES-256 key that seals each TOTP secret. Printing it yields "redacted".
// The zero Key is not set: enrollment is off and no TOTP code is accepted.
type Key struct {
	users.Redacted
	raw [keySize]byte
	set bool
}

// ParseKey reads 32 bytes in standard base64. The error MUST NOT include the text.
func ParseKey(text string) (Key, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil || len(raw) != keySize {
		return Key{}, ErrInvalidKey
	}
	k := Key{set: true}
	copy(k.raw[:], raw)
	return k, nil
}

// Set reports whether the key was configured.
func (k Key) Set() bool {
	return k.set
}

// SealedSecret is the AES-GCM nonce followed by the ciphertext of a Secret.
type SealedSecret []byte

// seal encrypts secret with userID as the additional data.
func (k Key) seal(secret Secret, userID users.ID) (SealedSecret, error) {
	aead, err := k.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(secret.raw)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("totp: nonce: %w", err)
	}
	id := userID.Bytes()
	return aead.Seal(nonce, nonce, secret.raw[:], id[:]), nil
}

// open decrypts sealed. It fails for a sealed secret of another user.
func (k Key) open(sealed SealedSecret, userID users.ID) (Secret, error) {
	aead, err := k.aead()
	if err != nil {
		return Secret{}, err
	}
	if len(sealed) < aead.NonceSize() {
		return Secret{}, errors.New("totp: sealed secret is too short")
	}
	id := userID.Bytes()
	nonce, body := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	raw, err := aead.Open(nil, nonce, body, id[:])
	if err != nil || len(raw) != secretSize {
		return Secret{}, errors.New("totp: sealed secret does not open")
	}
	var secret Secret
	copy(secret.raw[:], raw)
	return secret, nil
}

func (k Key) aead() (cipher.AEAD, error) {
	if !k.set {
		return nil, ErrKeyMissing
	}
	block, err := aes.NewCipher(k.raw[:])
	if err != nil {
		return nil, fmt.Errorf("totp: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("totp: cipher: %w", err)
	}
	return aead, nil
}
