// Package passkeytest is a software authenticator with one ES256 key.
// It builds the JSON a browser posts after navigator.credentials.create and get, with attestation "none".
package passkeytest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// credentialIDLength is the length of CredentialID. Create writes it as the 2-byte length field.
const credentialIDLength = 32

const (
	flagUserPresent  byte = 0x01
	flagUserVerified byte = 0x04
	flagAttested     byte = 0x40
)

// Authenticator keeps one credential for one relying party.
// Each response adds one to SignCount and sends the result.
// CredentialID MUST keep credentialIDLength bytes.
// SkipUserVerification clears the UV flag of the next responses.
type Authenticator struct {
	RelyingPartyID       string
	Origin               string
	CredentialID         []byte
	SignCount            uint32
	SkipUserVerification bool
	key                  *ecdsa.PrivateKey
}

// New makes a key and a random credential id.
func New(t testing.TB, relyingPartyID, origin string) *Authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, credentialIDLength)
	_, _ = rand.Read(id)
	return &Authenticator{RelyingPartyID: relyingPartyID, Origin: origin, CredentialID: id, key: key}
}

// Create returns the attestation JSON for challenge.
func (a *Authenticator) Create(t testing.TB, challenge []byte) []byte {
	t.Helper()
	ecdh, err := a.key.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	point := ecdh.Bytes()
	coseKey, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: point[1:33],
		YCoord: point[33:],
	})
	if err != nil {
		t.Fatal(err)
	}
	authData := a.authData(flagAttested)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, credentialIDLength)
	authData = append(authData, a.CredentialID...)
	authData = append(authData, coseKey...)
	attestation, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a.credentialJSON(t, map[string]any{
		"clientDataJSON":    encode(a.clientData(t, "webauthn.create", challenge)),
		"attestationObject": encode(attestation),
		"transports":        []string{"internal"},
	})
}

// Get returns the assertion JSON for challenge, signed by the key, from the user with userHandle.
func (a *Authenticator) Get(t testing.TB, challenge, userHandle []byte) []byte {
	t.Helper()
	clientData := a.clientData(t, "webauthn.get", challenge)
	authData := a.authData(0)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return a.credentialJSON(t, map[string]any{
		"clientDataJSON":    encode(clientData),
		"authenticatorData": encode(authData),
		"signature":         encode(signature),
		"userHandle":        encode(userHandle),
	})
}

func (a *Authenticator) authData(extra byte) []byte {
	rpHash := sha256.Sum256([]byte(a.RelyingPartyID))
	flags := flagUserPresent | extra
	if !a.SkipUserVerification {
		flags |= flagUserVerified
	}
	a.SignCount++
	out := append([]byte{}, rpHash[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, a.SignCount)
}

func (a *Authenticator) clientData(t testing.TB, kind string, challenge []byte) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"type":        kind,
		"challenge":   encode(challenge),
		"origin":      a.Origin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (a *Authenticator) credentialJSON(t testing.TB, response map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"id":                     encode(a.CredentialID),
		"rawId":                  encode(a.CredentialID),
		"type":                   "public-key",
		"response":               response,
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Challenge decodes the base64url challenge of the options a server sent.
func Challenge(t testing.TB, encoded string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func encode(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}
