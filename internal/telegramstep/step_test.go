package telegramstep

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/loginflow"
	"github.com/popoffvg/miniauth/internal/telegramstep/telegramtest"
	"github.com/popoffvg/miniauth/internal/users"
)

type memoryIdentities map[users.Subject]users.ID

func (m memoryIdentities) FindExternalIdentity(_ context.Context, account users.ExternalAccount) (users.Identity, error) {
	userID, ok := m[account.Subject]
	if !ok || account.Kind != users.KindTelegram {
		return users.Identity{}, users.ErrNotFound
	}
	return users.Identity{UserID: userID, Kind: account.Kind, Subject: account.Subject}, nil
}

type memoryProofs struct {
	stored map[ProofHash]time.Time
}

func (m *memoryProofs) Use(_ context.Context, hash ProofHash, expiresAt time.Time) error {
	if _, ok := m.stored[hash]; ok {
		return ErrReplay
	}
	m.stored[hash] = expiresAt
	return nil
}

func (m *memoryProofs) Cleanup(_ context.Context, now time.Time) error {
	for hash, expiresAt := range m.stored {
		if !expiresAt.After(now) {
			delete(m.stored, hash)
		}
	}
	return nil
}

type recordedFlow struct {
	events []loginflow.Event
}

func (f *recordedFlow) Apply(_ context.Context, event loginflow.Event) error {
	f.events = append(f.events, event)
	return nil
}

var testNow = time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)

func newTestStep(t *testing.T, identities memoryIdentities) *Step {
	t.Helper()
	name, err := ParseBotName(telegramtest.BotName)
	require.NoError(t, err)
	step, err := NewStep(Config{BotName: name, BotToken: ParseBotToken(telegramtest.BotToken)}, identities, &memoryProofs{stored: map[ProofHash]time.Time{}})
	require.NoError(t, err)
	step.now = func() time.Time { return testNow }
	return step
}

func parse(t *testing.T, query url.Values) AuthData {
	t.Helper()
	data, err := ParseAuthData(query)
	require.NoError(t, err)
	return data
}

func TestFinishLinkedAccount(t *testing.T) {
	userID := users.NewID()
	subject, err := users.ParseSubject("4242")
	require.NoError(t, err)
	step := newTestStep(t, memoryIdentities{subject: userID})
	flow := &recordedFlow{}

	outcome, err := step.Finish(t.Context(), flow, parse(t, telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(4242, testNow))))
	require.NoError(t, err)
	assert.True(t, outcome.Linked())
	assert.Equal(t, userID, outcome.UserID)
	require.Len(t, flow.events, 1)
	assert.Equal(t, loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorTelegram, UserID: userID}, flow.events[0])
}

func TestFinishLinkedAccountWithTOTPNeedsASecondFactor(t *testing.T) {
	userID := users.NewID()
	subject, err := users.ParseSubject("4343")
	require.NoError(t, err)
	step := newTestStep(t, memoryIdentities{subject: userID})
	step.secondFactors = enrolledUsers{userID: true}
	flow := &recordedFlow{}

	_, err = step.Finish(t.Context(), flow, parse(t, telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(4343, testNow))))
	require.NoError(t, err)
	require.Len(t, flow.events, 1)
	assert.Equal(t, loginflow.Event{Kind: loginflow.EventStepPassed, Factor: loginflow.FactorTelegram, UserID: userID, NeedsSecond: true}, flow.events[0])
}

// enrolledUsers reports a second factor for each user set to true.
type enrolledUsers map[users.ID]bool

func (e enrolledUsers) HasSecondFactor(_ context.Context, userID users.ID) (bool, error) {
	return e[userID], nil
}

func TestFinishUnknownAccount(t *testing.T) {
	step := newTestStep(t, memoryIdentities{})
	flow := &recordedFlow{}

	outcome, err := step.Finish(t.Context(), flow, parse(t, telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(7, testNow))))
	require.NoError(t, err)
	assert.False(t, outcome.Linked())
	assert.Equal(t, users.KindTelegram, outcome.Unlinked.Kind)
	assert.Equal(t, "7", outcome.Unlinked.Subject.String())
	require.Len(t, flow.events, 1)
	assert.True(t, flow.events[0].UnknownAccount)
}

func TestFinishRefusesBadData(t *testing.T) {
	signed := func(edit func(url.Values)) url.Values {
		fields := telegramtest.Fields(4242, testNow)
		fields.Set("photo_url", "https://t.example.test/a.jpg")
		query := telegramtest.Sign(telegramtest.BotToken, fields)
		edit(query)
		return query
	}
	tests := []struct {
		name  string
		query url.Values
		want  error
	}{
		{"another bot token", telegramtest.Sign("987654321:another-token", telegramtest.Fields(4242, testNow)), ErrBadHash},
		{"a changed field", signed(func(q url.Values) { q.Set("first_name", "Eve") }), ErrBadHash},
		{"a changed id", signed(func(q url.Values) { q.Set("id", "4243") }), ErrBadHash},
		{"an added field", signed(func(q url.Values) { q.Set("extra", "1") }), ErrBadHash},
		{"a removed field", signed(func(q url.Values) { q.Del("photo_url") }), ErrBadHash},
		{"a flipped hash", signed(func(q url.Values) { q.Set("hash", flipHex(q.Get("hash"))) }), ErrBadHash},
		{"an old auth_date", telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(4242, testNow.Add(-MaxAge))), ErrStale},
		{"a future auth_date", telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(4242, testNow.Add(MaxClockSkew+time.Second))), ErrStale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := newTestStep(t, memoryIdentities{})
			flow := &recordedFlow{}
			_, err := step.Finish(t.Context(), flow, parse(t, tt.query))
			require.ErrorIs(t, err, tt.want)
			assert.Empty(t, flow.events)
		})
	}
}

func TestFinishAcceptsAnUnknownSignedField(t *testing.T) {
	step := newTestStep(t, memoryIdentities{})
	fields := telegramtest.Fields(4242, testNow.Add(-MaxAge+time.Second))
	fields.Set("future_field", "x")
	_, err := step.Finish(t.Context(), &recordedFlow{}, parse(t, telegramtest.Sign(telegramtest.BotToken, fields)))
	require.NoError(t, err)
}

func TestFinishRefusesAReplay(t *testing.T) {
	step := newTestStep(t, memoryIdentities{})
	data := parse(t, telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(4242, testNow)))
	_, err := step.Finish(t.Context(), &recordedFlow{}, data)
	require.NoError(t, err)

	flow := &recordedFlow{}
	_, err = step.Finish(t.Context(), flow, data)
	require.ErrorIs(t, err, ErrReplay)
	assert.Empty(t, flow.events)
}

func TestParseAuthDataRefusesMalformedData(t *testing.T) {
	valid := telegramtest.Sign(telegramtest.BotToken, telegramtest.Fields(4242, testNow))
	edit := func(change func(url.Values)) url.Values {
		query := url.Values{}
		for key, values := range valid {
			query[key] = append([]string(nil), values...)
		}
		change(query)
		return query
	}
	for name, query := range map[string]url.Values{
		"empty":               {},
		"no hash":             edit(func(q url.Values) { q.Del("hash") }),
		"short hash":          edit(func(q url.Values) { q.Set("hash", "abcd") }),
		"no id":               edit(func(q url.Values) { q.Del("id") }),
		"id with a zero":      edit(func(q url.Values) { q.Set("id", "04242") }),
		"negative id":         edit(func(q url.Values) { q.Set("id", "-1") }),
		"no auth_date":        edit(func(q url.Values) { q.Del("auth_date") }),
		"text auth_date":      edit(func(q url.Values) { q.Set("auth_date", "today") }),
		"a repeated field":    edit(func(q url.Values) { q.Add("first_name", "Eve") }),
		"too many fields":     edit(func(q url.Values) { addFields(q, maxFields) }),
		"an empty field name": edit(func(q url.Values) { q.Set("", "x") }),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAuthData(query)
			require.ErrorIs(t, err, ErrBadData)
			for _, values := range valid {
				assert.NotContains(t, err.Error(), values[0])
			}
		})
	}
}

func TestConfigKeepsTheTokenOutOfPrints(t *testing.T) {
	token := ParseBotToken(telegramtest.BotToken)
	config := Config{BotToken: token}
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v %s", token, config, config, token), telegramtest.BotToken)

	_, err := NewStep(Config{BotToken: token}, memoryIdentities{}, &memoryProofs{})
	require.ErrorIs(t, err, ErrConfig)
	for _, bad := range []string{"bot", "has space_bot", "a_name_that_is_much_too_long_for_a_bot"} {
		_, err := ParseBotName(bad)
		require.ErrorIs(t, err, ErrConfig, bad)
	}
}

func flipHex(raw string) string {
	if raw[0] == '0' {
		return "1" + raw[1:]
	}
	return "0" + raw[1:]
}

func addFields(q url.Values, n int) {
	for i := range n {
		q.Set("f_"+strings.Repeat("x", i+1), "x")
	}
}

// A reshaped query keeps the check string and the hash of the signed data, but moves `id`.
func TestParseAuthDataRefusesAReshapedCheckString(t *testing.T) {
	signed := telegramtest.Sign(telegramtest.BotToken, url.Values{
		"first_name": {"Ada\nid=123"},
		"id":         {"456"},
		"username":   {"ada"},
		"auth_date":  {strconv.FormatInt(testNow.Unix(), 10)},
	})
	reshaped := url.Values{
		"first_name":       {"Ada"},
		"id":               {"123"},
		"id=456\nusername": {"ada"},
		"auth_date":        signed["auth_date"],
		"hash":             signed["hash"],
	}
	flat := func(q url.Values) AuthData {
		fields := map[string]string{}
		for key, values := range q {
			fields[key] = values[0]
		}
		return AuthData{fields: fields}
	}
	require.Equal(t, flat(signed).checkString(), flat(reshaped).checkString(), "the reshaped query MUST keep the signed check string")
	for name, query := range map[string]url.Values{"signed": signed, "reshaped": reshaped} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseAuthData(query)
			require.ErrorIs(t, err, ErrBadData)
		})
	}
	for name, query := range map[string]url.Values{
		"an upper case key":  {"First_name": {"Ada"}},
		"a key with a digit": {"name1": {"Ada"}},
	} {
		t.Run(name, func(t *testing.T) {
			fields := telegramtest.Fields(4242, testNow)
			for key, values := range query {
				fields[key] = values
			}
			_, err := ParseAuthData(telegramtest.Sign(telegramtest.BotToken, fields))
			require.ErrorIs(t, err, ErrBadData)
		})
	}
}
