package googlestep

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/googlestep/oidctest"
	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/users"
)

const testFlow loginflow.FlowID = "11111111-1111-4111-8111-111111111111"

type memoryChallenges struct {
	mu     sync.Mutex
	stored map[loginflow.FlowID]loginflow.Challenge
}

func (m *memoryChallenges) SaveChallenge(_ context.Context, id loginflow.FlowID, challenge loginflow.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stored[id] = challenge
	return nil
}

func (m *memoryChallenges) TakeChallenge(_ context.Context, id loginflow.FlowID) (loginflow.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	challenge, ok := m.stored[id]
	if !ok {
		return nil, loginflow.ErrChallengeNotFound
	}
	delete(m.stored, id)
	return challenge, nil
}

type memoryIdentities map[users.Subject]users.ID

func (m memoryIdentities) FindExternalIdentity(_ context.Context, account users.ExternalAccount) (users.Identity, error) {
	userID, ok := m[account.Subject]
	if !ok || account.Kind != users.KindGoogle {
		return users.Identity{}, users.ErrNotFound
	}
	return users.Identity{UserID: userID, Kind: account.Kind, Subject: account.Subject}, nil
}

type recordedFlow struct {
	events []loginflow.Event
}

func (f *recordedFlow) Apply(_ context.Context, event loginflow.Event) error {
	f.events = append(f.events, event)
	return nil
}

type harness struct {
	step       *Step
	provider   *oidctest.Provider
	challenges *memoryChallenges
}

func newHarness(t *testing.T, identities memoryIdentities) harness {
	t.Helper()
	provider := oidctest.New(t)
	challenges := &memoryChallenges{stored: map[loginflow.FlowID]loginflow.Challenge{}}
	step, err := NewStep(Config{
		Issuer:       Issuer(provider.Issuer()),
		ClientID:     ParseClientID(oidctest.ClientID),
		ClientSecret: ParseClientSecret(oidctest.ClientSecret),
		RedirectURL:  "https://id.example.test/login/google/callback",
	}, identities, challenges, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = step.Close() })
	go step.Watch(t.Context(), 10*time.Millisecond)
	require.Eventually(t, step.Available, 5*time.Second, 10*time.Millisecond)
	return harness{step: step, provider: provider, challenges: challenges}
}

// authorize opens the Google URL like a browser and returns the state and the code of the callback.
func authorize(t *testing.T, authURL AuthURL) (State, Code) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, string(authURL), nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusFound, resp.StatusCode)
	back, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	return State(back.Query().Get("state")), Code(back.Query().Get("code"))
}

func TestFinishPassesAKnownSubject(t *testing.T) {
	userID := users.NewID()
	subject, err := users.ParseSubject("known-sub")
	require.NoError(t, err)
	h := newHarness(t, memoryIdentities{subject: userID})
	h.provider.SetSubject("known-sub")

	authURL, verifier, err := h.step.Begin(t.Context(), testFlow)
	require.NoError(t, err)
	assert.NotContains(t, string(authURL), verifier.CookieValue())
	stored := h.challenges.stored[testFlow]
	assert.NotContains(t, string(stored), verifier.CookieValue())
	state, code := authorize(t, authURL)

	// The user has TOTP, so the flow MUST still ask for a second factor.
	h.step.config.SecondFactors = enrolledUsers{userID: true}
	flow := &recordedFlow{}
	outcome, err := h.step.Finish(t.Context(), flow, testFlow, verifier, state, code)
	require.NoError(t, err)
	assert.True(t, outcome.Linked())
	assert.Equal(t, userID, outcome.UserID)
	want := loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorGoogle, UserID: userID, NeedsSecond: true}
	assert.Equal(t, []loginflow.Event{want}, flow.events)

	_, err = h.step.Finish(t.Context(), flow, testFlow, verifier, state, code)
	require.ErrorIs(t, err, ErrBadCallback, "a challenge is good for one callback")
}

func TestFinishKeepsAnUnknownSubjectUnlinked(t *testing.T) {
	h := newHarness(t, memoryIdentities{})
	h.provider.SetSubject("unknown-sub")
	authURL, verifier, err := h.step.Begin(t.Context(), testFlow)
	require.NoError(t, err)
	state, code := authorize(t, authURL)

	flow := &recordedFlow{}
	outcome, err := h.step.Finish(t.Context(), flow, testFlow, verifier, state, code)
	require.NoError(t, err)
	assert.False(t, outcome.Linked())
	assert.Equal(t, users.KindGoogle, outcome.Unlinked.Kind)
	assert.Equal(t, "unknown-sub", outcome.Unlinked.Subject.String())
	assert.Equal(t, []loginflow.Event{{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorGoogle, UnknownAccount: true}}, flow.events)
}

func TestFinishRefusesAForeignCallback(t *testing.T) {
	h := newHarness(t, memoryIdentities{})
	h.provider.SetSubject("some-sub")
	other, err := ParseVerifier("another-verifier-value")
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(*State, *Verifier, *Code)
		want   error
	}{
		{name: "bad state", mutate: func(s *State, _ *Verifier, _ *Code) { *s += "x" }, want: ErrBadCallback},
		{name: "bad verifier", mutate: func(_ *State, v *Verifier, _ *Code) { *v = other }, want: ErrBadCallback},
		{name: "empty code", mutate: func(_ *State, _ *Verifier, c *Code) { *c = "" }, want: ErrBadCallback},
		{name: "unknown code", mutate: func(_ *State, _ *Verifier, c *Code) { *c += "x" }, want: ErrBadCallback},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, verifier, err := h.step.Begin(t.Context(), testFlow)
			require.NoError(t, err)
			state, code := authorize(t, authURL)
			tt.mutate(&state, &verifier, &code)
			flow := &recordedFlow{}
			_, err = h.step.Finish(t.Context(), flow, testFlow, verifier, state, code)
			require.ErrorIs(t, err, tt.want)
			assert.Empty(t, flow.events)
		})
	}
}

func TestFinishRefusesABadIDToken(t *testing.T) {
	h := newHarness(t, memoryIdentities{})
	h.provider.SetSubject("some-sub")
	tests := []struct {
		claim string
		value any
	}{
		{claim: "nonce", value: "not-the-nonce-of-the-request"},
		{claim: "aud", value: "another-client"},
		{claim: "iss", value: "https://issuer.example.test"},
		{claim: "exp", value: time.Now().Add(-time.Hour).Unix()},
		{claim: "sub", value: ""},
	}
	for _, tt := range tests {
		t.Run(tt.claim, func(t *testing.T) {
			h.provider.SetClaim(tt.claim, tt.value)
			t.Cleanup(h.provider.ResetClaims)
			authURL, verifier, err := h.step.Begin(t.Context(), testFlow)
			require.NoError(t, err)
			state, code := authorize(t, authURL)
			flow := &recordedFlow{}
			_, err = h.step.Finish(t.Context(), flow, testFlow, verifier, state, code)
			require.ErrorIs(t, err, ErrBadToken)
			assert.Empty(t, flow.events)
		})
	}
}

func TestWatchMarksTheStepUnavailableWhileDiscoveryFails(t *testing.T) {
	h := newHarness(t, memoryIdentities{})
	h.provider.SetDiscoveryDown(true)
	require.Eventually(t, func() bool { return !h.step.Available() }, 5*time.Second, 10*time.Millisecond)
	_, _, err := h.step.Begin(t.Context(), testFlow)
	require.ErrorIs(t, err, ErrUnavailable)

	h.provider.SetDiscoveryDown(false)
	require.Eventually(t, h.step.Available, 5*time.Second, 10*time.Millisecond)
	_, _, err = h.step.Begin(t.Context(), testFlow)
	require.NoError(t, err)
}

func TestNewStepRequiresTheConfig(t *testing.T) {
	_, err := NewStep(Config{Issuer: "https://issuer.example.test"}, memoryIdentities{}, &memoryChallenges{}, nil)
	require.ErrorIs(t, err, ErrConfig)
}

func TestClientSecretPrintsRedacted(t *testing.T) {
	secret := ParseClientSecret("very-secret-value")
	assert.Equal(t, "redacted", secret.String())
	verifier, err := ParseVerifier("verifier-value")
	require.NoError(t, err)
	assert.Equal(t, "redacted", verifier.String())
}

// enrolledUsers reports a second factor for each user set to true.
type enrolledUsers map[users.ID]bool

func (e enrolledUsers) HasSecondFactor(_ context.Context, userID users.ID) (bool, error) {
	return e[userID], nil
}
