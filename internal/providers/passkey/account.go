package passkey

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/popoffvg/miniauth/internal/users"
)

// account is a user as the webauthn library reads it.
// The user handle is the 16 bytes of the user id: it names no person.
type account struct {
	id       users.ID
	login    users.Login
	passkeys []Passkey
}

var _ webauthn.User = account{}

func (a account) WebAuthnID() []byte {
	raw := a.id.Bytes()
	return raw[:]
}

func (a account) WebAuthnName() string {
	return a.login.String()
}

func (a account) WebAuthnDisplayName() string {
	return a.login.String()
}

func (a account) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(a.passkeys))
	for _, passkey := range a.passkeys {
		out = append(out, credentialOf(passkey))
	}
	return out
}

func credentialOf(passkey Passkey) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(passkey.Transports))
	for _, transport := range passkey.Transports {
		transports = append(transports, protocol.AuthenticatorTransport(transport))
	}
	return webauthn.Credential{
		ID:        passkey.CredentialID,
		PublicKey: passkey.PublicKey,
		Transport: transports,
		Flags:     webauthn.CredentialFlags{UserVerified: true, BackupEligible: passkey.BackupEligible},
		Authenticator: webauthn.Authenticator{
			AAGUID:    passkey.AAGUID[:],
			SignCount: uint32(passkey.SignCount),
		},
	}
}

// descriptors lists the credentials of passkeys, so a browser does not register one authenticator twice.
func descriptors(passkeys []Passkey) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(passkeys))
	for _, passkey := range passkeys {
		credential := credentialOf(passkey)
		out = append(out, credential.Descriptor())
	}
	return out
}
