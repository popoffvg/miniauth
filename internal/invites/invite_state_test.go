package invites

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextCoversEveryPair(t *testing.T) {
	const refused = InviteState("")
	events := []InviteEvent{EventAccept, EventExpire}
	want := map[InviteState][]InviteState{
		StateOpen:    {StateUsed, StateExpired},
		StateUsed:    {refused, refused},
		StateExpired: {refused, refused},
	}
	for state, row := range want {
		for i, event := range events {
			t.Run(string(state)+"/"+string(event), func(t *testing.T) {
				next, err := Next(state, event)
				if row[i] == refused {
					require.ErrorIs(t, err, ErrNoTransition)
					assert.Equal(t, state, next)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, row[i], next)
			})
		}
	}
}
