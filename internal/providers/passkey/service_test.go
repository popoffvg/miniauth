package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/providers/passkey"
	"github.com/popoffvg/miniauth/internal/providers/passkey/passkeytest"
	"github.com/popoffvg/miniauth/internal/sessions"
	"github.com/popoffvg/miniauth/internal/users"
)

const testOrigin = "https://id.example.test"

func TestPasskeyAloneCompletesALogin(t *testing.T) {
	for _, needsSecond := range []bool{false, true} {
		fx := newFixture(t)
		user := fx.user(t, "ada")
		key := fx.register(t, user)

		flow := fx.flow(t)
		flow.state.NeedsSecond = needsSecond
		got, err := fx.verify(t, flow, key, user)
		require.NoError(t, err)
		assert.Equal(t, user.ID, got)
		assert.Equal(t, loginflow.StateComplete, flow.state.State)
		assert.True(t, flow.state.Factors.Has(loginflow.FactorPasskey))
		assert.False(t, flow.state.Factors.Has(loginflow.FactorPassword))

		list, err := fx.service.List(t.Context(), user.ID)
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, passkey.SignCount(key.SignCount), list[0].SignCount)
		assert.False(t, list[0].LastUsedAt.IsZero())
	}
}

func TestReplayedChallengeIsRefused(t *testing.T) {
	fx := newFixture(t)
	user := fx.user(t, "ada")
	key := fx.register(t, user)
	flow := fx.flow(t)
	options, err := fx.service.BeginLogin(t.Context(), flow.state.ID)
	require.NoError(t, err)
	challenge := []byte(options.Response.Challenge)
	handle := user.ID.Bytes()

	first := key.Get(t, challenge, handle[:])
	_, err = fx.service.Verify(t.Context(), flow, first)
	require.NoError(t, err)

	flow.state = loginflow.LoginFlow{ID: flow.state.ID, State: loginflow.StateAwaiting, Kind: loginflow.KindLogin}
	_, err = fx.service.Verify(t.Context(), flow, first)
	require.ErrorIs(t, err, loginflow.ErrChallengeNotFound)
	_, err = fx.service.Verify(t.Context(), flow, key.Get(t, challenge, handle[:]))
	require.ErrorIs(t, err, loginflow.ErrChallengeNotFound)
	assert.Equal(t, loginflow.StateAwaiting, flow.state.State)
}

func TestUserVerificationIsRequired(t *testing.T) {
	fx := newFixture(t)
	user := fx.user(t, "ada")

	unverified := passkeytest.New(t, "example.test", testOrigin)
	unverified.SkipUserVerification = true
	options, err := fx.service.BeginRegistration(t.Context(), fx.flow(t).state.ID, user)
	require.NoError(t, err)
	_, err = fx.service.Register(t.Context(), fx.lastFlow, user, fx.name(t), unverified.Create(t, []byte(options.Response.Challenge)))
	require.ErrorIs(t, err, passkey.ErrUserNotVerified)

	key := fx.register(t, user)
	key.SkipUserVerification = true
	flow := fx.flow(t)
	_, err = fx.verify(t, flow, key, user)
	require.ErrorIs(t, err, passkey.ErrUserNotVerified)
	assert.Equal(t, loginflow.StateAwaiting, flow.state.State)
}

func TestCounterThatGoesBackIsRefused(t *testing.T) {
	fx := newFixture(t)
	user := fx.user(t, "ada")
	key := fx.register(t, user)
	key.SignCount = 10
	_, err := fx.verify(t, fx.flow(t), key, user)
	require.NoError(t, err)

	key.SignCount = 5
	flow := fx.flow(t)
	_, err = fx.verify(t, flow, key, user)
	require.ErrorIs(t, err, passkey.ErrClonedAuthenticator)
	assert.Equal(t, loginflow.StateAwaiting, flow.state.State)
}

func TestPasskeyOfAnotherUserDoesNotPass(t *testing.T) {
	fx := newFixture(t)
	ada := fx.user(t, "ada")
	bea := fx.user(t, "bea")
	key := fx.register(t, ada)

	_, err := fx.verify(t, fx.flow(t), key, bea)
	require.ErrorIs(t, err, passkey.ErrCeremony)

	list, err := fx.service.List(t.Context(), ada.ID)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.ErrorIs(t, fx.service.Delete(t.Context(), bea.ID, list[0].ID), passkey.ErrNotFound)
	require.NoError(t, fx.service.Delete(t.Context(), ada.ID, list[0].ID))
}

func TestRegistrationOptionsRequireADiscoverableCredential(t *testing.T) {
	fx := newFixture(t)
	user := fx.user(t, "ada")
	fx.register(t, user)
	options, err := fx.service.BeginRegistration(t.Context(), fx.flow(t).state.ID, user)
	require.NoError(t, err)
	selection := options.Response.AuthenticatorSelection
	assert.Equal(t, protocol.ResidentKeyRequirementRequired, selection.ResidentKey)
	assert.Equal(t, protocol.VerificationRequired, selection.UserVerification)
	assert.Equal(t, "example.test", options.Response.RelyingParty.ID)
	assert.Equal(t, "miniauth", options.Response.RelyingParty.Name)
	assert.Len(t, options.Response.CredentialExcludeList, 1)

	login, err := fx.service.BeginLogin(t.Context(), fx.flow(t).state.ID)
	require.NoError(t, err)
	assert.Empty(t, login.Response.AllowedCredentials)
	assert.Equal(t, protocol.VerificationRequired, login.Response.UserVerification)
	_, err = json.Marshal(login)
	require.NoError(t, err)
}

func TestRelyingPartyComesFromTheCookieDomain(t *testing.T) {
	tests := []struct {
		domain string
		origin string
		wantID passkey.RelyingPartyID
		ok     bool
	}{
		{domain: ".example.test", origin: "https://id.example.test", wantID: "example.test", ok: true},
		{domain: "", origin: "https://id.example.test:8443", wantID: "id.example.test", ok: true},
		{domain: "", origin: "https://127.0.0.1:8443", ok: false},
		{domain: "", origin: "ftp://id.example.test", ok: false},
		{domain: ".example.test", origin: "https://example.test", wantID: "example.test", ok: true},
		{domain: ".other.test", origin: "https://id.example.test", ok: false},
		{domain: ".ample.test", origin: "https://id.example.test", ok: false},
		{domain: ".id.example.test", origin: "https://example.test", ok: false},
	}
	for _, tt := range tests {
		domain, err := sessions.ParseDomain(tt.domain)
		require.NoError(t, err)
		origin, err := url.Parse(tt.origin)
		require.NoError(t, err)
		party, err := passkey.NewRelyingParty(domain, origin)
		if !tt.ok {
			require.ErrorIs(t, err, passkey.ErrRelyingParty, tt.origin)
			continue
		}
		require.NoError(t, err, tt.origin)
		assert.Equal(t, tt.wantID, party.ID)
		assert.Equal(t, passkey.Origin(tt.origin), party.Origin)
	}
}

type fixture struct {
	service  *passkey.Service
	passkeys *memPasskeys
	flows    *memChallenges
	lastFlow loginflow.FlowID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	domain, err := sessions.ParseDomain(".example.test")
	require.NoError(t, err)
	origin, err := url.Parse(testOrigin)
	require.NoError(t, err)
	party, err := passkey.NewRelyingParty(domain, origin)
	require.NoError(t, err)
	passkeys := &memPasskeys{}
	challenges := &memChallenges{open: map[loginflow.FlowID]loginflow.Challenge{}}
	service, err := passkey.NewService(party, passkeys, challenges)
	require.NoError(t, err)
	return &fixture{service: service, passkeys: passkeys, flows: challenges}
}

func (f *fixture) user(t *testing.T, raw string) users.User {
	t.Helper()
	login, err := users.ParseLogin(raw)
	require.NoError(t, err)
	return users.User{ID: users.NewID(), Login: login}
}

func (f *fixture) name(t *testing.T) passkey.Name {
	t.Helper()
	name, err := passkey.ParseName("laptop")
	require.NoError(t, err)
	return name
}

// flow starts a login flow in StateAwaiting that the challenge store knows.
func (f *fixture) flow(t *testing.T) *memFlow {
	t.Helper()
	id, err := loginflow.NewFlowID()
	require.NoError(t, err)
	f.flows.mu.Lock()
	f.flows.known = append(f.flows.known, id)
	f.flows.mu.Unlock()
	f.lastFlow = id
	return &memFlow{state: loginflow.LoginFlow{ID: id, State: loginflow.StateAwaiting, Kind: loginflow.KindLogin}}
}

func (f *fixture) register(t *testing.T, user users.User) *passkeytest.Authenticator {
	t.Helper()
	key := passkeytest.New(t, "example.test", testOrigin)
	flow := f.flow(t)
	options, err := f.service.BeginRegistration(t.Context(), flow.state.ID, user)
	require.NoError(t, err)
	handle := user.ID.Bytes()
	userHandle, ok := options.Response.User.ID.(protocol.URLEncodedBase64)
	require.True(t, ok)
	require.True(t, bytes.Equal(handle[:], userHandle))
	_, err = f.service.Register(t.Context(), flow.state.ID, user, f.name(t), key.Create(t, []byte(options.Response.Challenge)))
	require.NoError(t, err)
	return key
}

// verify signs the challenge of a new login ceremony on flow as the user with handle of user.
func (f *fixture) verify(t *testing.T, flow *memFlow, key *passkeytest.Authenticator, user users.User) (users.ID, error) {
	t.Helper()
	options, err := f.service.BeginLogin(t.Context(), flow.state.ID)
	require.NoError(t, err)
	handle := user.ID.Bytes()
	return f.service.Verify(t.Context(), flow, key.Get(t, []byte(options.Response.Challenge), handle[:]))
}

type memFlow struct {
	state loginflow.LoginFlow
}

func (m *memFlow) Get() loginflow.LoginFlow {
	return m.state
}

func (m *memFlow) Apply(_ context.Context, event loginflow.Event) error {
	next, err := m.state.Next(event)
	if err != nil {
		return err
	}
	m.state = next
	return nil
}

type memChallenges struct {
	mu    sync.Mutex
	known []loginflow.FlowID
	open  map[loginflow.FlowID]loginflow.Challenge
}

func (m *memChallenges) SaveChallenge(_ context.Context, id loginflow.FlowID, challenge loginflow.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Contains(m.known, id) {
		return loginflow.ErrFlowNotFound
	}
	m.open[id] = challenge
	return nil
}

func (m *memChallenges) TakeChallenge(_ context.Context, id loginflow.FlowID) (loginflow.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	challenge, ok := m.open[id]
	if !ok {
		return nil, loginflow.ErrChallengeNotFound
	}
	delete(m.open, id)
	return challenge, nil
}

type memPasskeys struct {
	mu   sync.Mutex
	rows []passkey.Passkey
}

func (m *memPasskeys) Create(_ context.Context, passkeyRow passkey.Passkey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.rows {
		if bytes.Equal(row.CredentialID, passkeyRow.CredentialID) {
			return passkey.ErrDuplicate
		}
	}
	m.rows = append(m.rows, passkeyRow)
	return nil
}

func (m *memPasskeys) FindByCredential(_ context.Context, id passkey.CredentialID) (passkey.Passkey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, row := range m.rows {
		if bytes.Equal(row.CredentialID, id) {
			return row, nil
		}
	}
	return passkey.Passkey{}, passkey.ErrUnknownCredential
}

func (m *memPasskeys) List(_ context.Context, userID users.ID) ([]passkey.Passkey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []passkey.Passkey
	for _, row := range m.rows {
		if row.UserID == userID {
			out = append(out, row)
		}
	}
	return out, nil
}

func (m *memPasskeys) RecordUse(_ context.Context, id passkey.ID, prev, next passkey.SignCount, at time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, row := range m.rows {
		if row.ID == id && row.SignCount == prev {
			m.rows[i].SignCount = next
			m.rows[i].LastUsedAt = at
			return true, nil
		}
	}
	return false, nil
}

func (m *memPasskeys) Delete(_ context.Context, userID users.ID, id passkey.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, row := range m.rows {
		if row.ID == id && row.UserID == userID {
			m.rows = slices.Delete(m.rows, i, i+1)
			return nil
		}
	}
	return passkey.ErrNotFound
}
