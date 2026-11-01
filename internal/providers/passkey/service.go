package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

// Store keeps passkeys.
// Create MUST return ErrDuplicate when the credential id is stored.
// FindByCredential MUST return ErrUnknownCredential when no active user has the credential.
// RecordUse writes next and at only while the stored count is still prev. It reports whether it wrote.
// Delete MUST return ErrNotFound when userID has no passkey with id.
type Store interface {
	Create(ctx context.Context, passkey Passkey) error
	FindByCredential(ctx context.Context, id CredentialID) (Passkey, error)
	List(ctx context.Context, userID users.ID) ([]Passkey, error)
	RecordUse(ctx context.Context, id ID, prev, next SignCount, at time.Time) (bool, error)
	Delete(ctx context.Context, userID users.ID, id ID) error
}

// Flow is the login flow that receives the step result. *sfsm.PersistedSFSM from loginflow.LoginFlows.Open fits.
type Flow interface {
	Get() loginflow.LoginFlow
	Apply(ctx context.Context, event loginflow.Event) error
}

// Service runs the WebAuthn ceremonies and keeps the passkeys of users.
// Every ceremony requires user verification. A registration requires a discoverable credential,
// so a login needs no login name.
type Service struct {
	web        *webauthn.WebAuthn
	party      RelyingParty
	passkeys   Store
	challenges loginflow.ChallengeStore
	now        func() time.Time
}

// NewService returns a service that reads the clock from time.Now.
func NewService(party RelyingParty, passkeys Store, challenges loginflow.ChallengeStore) (*Service, error) {
	if passkeys == nil || challenges == nil {
		return nil, errors.New("passkey: store is missing")
	}
	requireResidentKey := true
	web, err := webauthn.New(&webauthn.Config{
		RPID:                  string(party.ID),
		RPDisplayName:         relyingPartyName,
		RPOrigins:             []string{string(party.Origin)},
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &requireResidentKey,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRelyingParty, err)
	}
	return &Service{web: web, party: party, passkeys: passkeys, challenges: challenges, now: time.Now}, nil
}

// BeginLogin stores a new challenge on the flow and returns the options for navigator.credentials.get.
// The options name no credential: the authenticator offers its discoverable credentials.
func (s *Service) BeginLogin(ctx context.Context, flowID loginflow.FlowID) (*protocol.CredentialAssertion, error) {
	options, session, err := s.web.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, fmt.Errorf("passkey: begin login: %w", err)
	}
	if err := s.storeChallenge(ctx, flowID, session.Challenge); err != nil {
		return nil, err
	}
	return options, nil
}

// Verify checks an assertion against the challenge of flow and sends EventStepPassed with FactorPasskey.
// The challenge is cleared first, so a second try with the same challenge fails with loginflow.ErrChallengeNotFound.
// A response without the UV flag is ErrUserNotVerified. A counter that does not move forward is ErrClonedAuthenticator.
func (s *Service) Verify(ctx context.Context, flow Flow, response AssertionResponse) (users.ID, error) {
	challenge, err := s.challenges.TakeChallenge(ctx, flow.Get().ID)
	if err != nil {
		return users.ID{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return users.ID{}, fmt.Errorf("%w: %w", ErrCeremony, err)
	}
	if !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		return users.ID{}, ErrUserNotVerified
	}
	passkey, err := s.passkeys.FindByCredential(ctx, CredentialID(parsed.RawID))
	if err != nil {
		return users.ID{}, err
	}
	session := webauthn.SessionData{
		Challenge:        encodeChallenge(challenge),
		RelyingPartyID:   string(s.party.ID),
		UserVerification: protocol.VerificationRequired,
	}
	owner := func(rawID, userHandle []byte) (webauthn.User, error) {
		handle := passkey.UserID.Bytes()
		if !bytes.Equal(rawID, passkey.CredentialID) || !bytes.Equal(userHandle, handle[:]) {
			return nil, ErrUnknownCredential
		}
		return account{id: passkey.UserID, passkeys: []Passkey{passkey}}, nil
	}
	if _, _, err = s.web.ValidatePasskeyLogin(owner, session, parsed); err != nil {
		return users.ID{}, fmt.Errorf("%w: %w", ErrCeremony, err)
	}
	next := SignCount(parsed.Response.AuthenticatorData.Counter)
	if !counterMoved(passkey.SignCount, next) {
		return users.ID{}, ErrClonedAuthenticator
	}
	wrote, err := s.passkeys.RecordUse(ctx, passkey.ID, passkey.SignCount, next, s.now().UTC())
	if err != nil {
		return users.ID{}, err
	}
	if !wrote {
		return users.ID{}, ErrClonedAuthenticator
	}
	event := loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorPasskey, UserID: passkey.UserID}
	if err := flow.Apply(ctx, event); err != nil {
		return users.ID{}, fmt.Errorf("passkey: apply %s: %w", event.Kind, err)
	}
	return passkey.UserID, nil
}

// BeginRegistration stores a new challenge on the flow and returns the options for navigator.credentials.create.
// The options exclude the passkeys user already has.
func (s *Service) BeginRegistration(ctx context.Context, flowID loginflow.FlowID, user users.User) (*protocol.CredentialCreation, error) {
	existing, err := s.passkeys.List(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	options, session, err := s.web.BeginRegistration(
		account{id: user.ID, login: user.Login},
		webauthn.WithExclusions(descriptors(existing)),
	)
	if err != nil {
		return nil, fmt.Errorf("passkey: begin registration: %w", err)
	}
	if err := s.storeChallenge(ctx, flowID, session.Challenge); err != nil {
		return nil, err
	}
	return options, nil
}

// Register checks an attestation against the challenge of the flow and stores the passkey for user.
// The challenge is cleared first, so it is used once. A credential without the UV flag is ErrUserNotVerified.
func (s *Service) Register(ctx context.Context, flowID loginflow.FlowID, user users.User, name Name, response AttestationResponse) (Passkey, error) {
	if name == (Name{}) {
		return Passkey{}, ErrName
	}
	challenge, err := s.challenges.TakeChallenge(ctx, flowID)
	if err != nil {
		return Passkey{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return Passkey{}, fmt.Errorf("%w: %w", ErrCeremony, err)
	}
	if !parsed.Response.AttestationObject.AuthData.Flags.HasUserVerified() {
		return Passkey{}, ErrUserNotVerified
	}
	holder := account{id: user.ID, login: user.Login}
	session := webauthn.SessionData{
		Challenge:        encodeChallenge(challenge),
		RelyingPartyID:   string(s.party.ID),
		UserID:           holder.WebAuthnID(),
		UserVerification: protocol.VerificationRequired,
		CredParams:       webauthn.CredentialParametersDefault(),
	}
	credential, err := s.web.CreateCredential(holder, session, parsed)
	if err != nil {
		return Passkey{}, fmt.Errorf("%w: %w", ErrCeremony, err)
	}
	passkey := Passkey{
		ID:             NewID(),
		UserID:         user.ID,
		CredentialID:   CredentialID(credential.ID),
		PublicKey:      PublicKey(credential.PublicKey),
		SignCount:      SignCount(credential.Authenticator.SignCount),
		Transports:     transportsOf(credential.Transport),
		BackupEligible: credential.Flags.BackupEligible,
		Name:           name,
		CreatedAt:      s.now().UTC(),
	}
	copy(passkey.AAGUID[:], credential.Authenticator.AAGUID)
	if err := s.passkeys.Create(ctx, passkey); err != nil {
		return Passkey{}, err
	}
	return passkey, nil
}

// List returns the passkeys of userID, oldest first.
func (s *Service) List(ctx context.Context, userID users.ID) ([]Passkey, error) {
	return s.passkeys.List(ctx, userID)
}

// Delete removes one passkey of userID. A passkey of another user is ErrNotFound.
func (s *Service) Delete(ctx context.Context, userID users.ID, id ID) error {
	return s.passkeys.Delete(ctx, userID, id)
}

func (s *Service) storeChallenge(ctx context.Context, flowID loginflow.FlowID, encoded string) error {
	challenge, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("passkey: challenge: %w", err)
	}
	return s.challenges.SaveChallenge(ctx, flowID, challenge)
}

func encodeChallenge(challenge loginflow.Challenge) string {
	return base64.RawURLEncoding.EncodeToString(challenge)
}

// counterMoved is false when the new count is not above the stored one.
// Two zero counts pass: the authenticator keeps no counter.
func counterMoved(stored, next SignCount) bool {
	return next > stored || stored == 0 && next == 0
}

func transportsOf(raw []protocol.AuthenticatorTransport) []Transport {
	out := make([]Transport, 0, len(raw))
	for _, transport := range raw {
		out = append(out, Transport(transport))
	}
	return out
}
