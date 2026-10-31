package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mailEnv(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestParseMail(t *testing.T) {
	const password = "smtp-password-stays-secret"
	tests := []struct {
		name    string
		env     map[string]string
		kind    MailKind
		wantErr error
	}{
		{name: "nothing set is off", env: nil, kind: MailOff},
		{name: "log only when asked", env: map[string]string{envMail: "log"}, kind: MailLog},
		{name: "an unknown mode", env: map[string]string{envMail: "smtp"}, wantErr: errMail},
		{name: "log and SMTP together", env: map[string]string{envMail: "log", envSMTPHost: "relay.example.test"}, wantErr: errMailBoth},
		{name: "SMTP without a host", env: map[string]string{envSMTPFrom: "id@example.test"}, wantErr: errSMTPWithout},
		{
			name: "SMTP",
			env: map[string]string{
				envSMTPHost: "relay.example.test", envSMTPPort: "2525", envSMTPUser: "miniauth",
				envSMTPPassword: password, envSMTPFrom: "id@example.test",
			},
			kind: MailSMTP,
		},
		{name: "SMTP without a sender", env: map[string]string{envSMTPHost: "relay.example.test"}, wantErr: errSMTPFrom},
		{name: "SMTP with a bad port", env: map[string]string{envSMTPHost: "relay.example.test", envSMTPPort: "x", envSMTPFrom: "id@example.test"}, wantErr: errSMTPPort},
		{
			name:    "SMTP user without a password",
			env:     map[string]string{envSMTPHost: "relay.example.test", envSMTPUser: "miniauth", envSMTPFrom: "id@example.test"},
			wantErr: errSMTPAuth,
		},
		{
			name:    "SMTP password without a user",
			env:     map[string]string{envSMTPHost: "relay.example.test", envSMTPPassword: password, envSMTPFrom: "id@example.test"},
			wantErr: errSMTPAuth,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mail, err := parseMail(mailEnv(tt.env))
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.NotContains(t, err.Error(), password)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.kind, mail.Kind)
			assert.NotContains(t, fmt.Sprintf("%v %+v", mail, mail), password)
		})
	}
}

func TestParseMailSMTPSettings(t *testing.T) {
	mail, err := parseMail(mailEnv(map[string]string{envSMTPHost: "relay.example.test", envSMTPFrom: "id@example.test"}))
	require.NoError(t, err)
	assert.Equal(t, "relay.example.test:587", mail.SMTP.Addr())
	assert.Equal(t, "id@example.test", mail.SMTP.From.String())
}
