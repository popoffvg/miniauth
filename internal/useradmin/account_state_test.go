package useradmin_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/popoffvg/miniauth/internal/useradmin"
	"github.com/popoffvg/miniauth/internal/users"
)

func TestNextCoversEveryPair(t *testing.T) {
	bob := users.NewID()
	at := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	other := useradmin.Actor{ID: users.NewID()}
	self := useradmin.Actor{ID: bob}
	active := useradmin.AccountState{User: bob, Status: useradmin.StatusActive}
	disabled := useradmin.AccountState{User: bob, Status: useradmin.StatusDisabled, DisabledAt: at}

	cases := []struct {
		name  string
		state useradmin.AccountState
		event useradmin.AccountEvent
		want  useradmin.AccountState
		err   error
	}{
		{"active/disable", active, useradmin.AccountEvent{Kind: useradmin.EventDisable, Actor: other, At: at}, disabled, nil},
		{"active/disable by the bootstrap token", active, useradmin.AccountEvent{Kind: useradmin.EventDisable, At: at}, disabled, nil},
		{"active/disable by itself", active, useradmin.AccountEvent{Kind: useradmin.EventDisable, Actor: self, At: at}, active, useradmin.ErrSelfDisable},
		{"active/enable", active, useradmin.AccountEvent{Kind: useradmin.EventEnable, Actor: other}, active, useradmin.ErrNoTransition},
		{"disabled/disable", disabled, useradmin.AccountEvent{Kind: useradmin.EventDisable, Actor: other, At: at.Add(time.Hour)}, disabled, useradmin.ErrNoTransition},
		{"disabled/disable by itself", disabled, useradmin.AccountEvent{Kind: useradmin.EventDisable, Actor: self, At: at}, disabled, useradmin.ErrSelfDisable},
		{"disabled/enable", disabled, useradmin.AccountEvent{Kind: useradmin.EventEnable, Actor: other}, active, nil},
		{"disabled/enable by itself", disabled, useradmin.AccountEvent{Kind: useradmin.EventEnable, Actor: self}, active, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next, err := useradmin.Next(tc.state, tc.event)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, next)
		})
	}
}
