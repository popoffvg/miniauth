package totp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNextCoversEveryPair(t *testing.T) {
	const refused = EnrollmentStage("")
	stages := []EnrollmentStage{StageNone, StagePending, StageConfirmed, StageDisabled}
	events := []EnrollmentEventKind{EventBegin, EventConfirm, EventExpire, EventDisable}
	want := map[EnrollmentStage][]EnrollmentStage{
		StageNone:      {StagePending, refused, refused, refused},
		StagePending:   {StagePending, StageConfirmed, StageNone, StageDisabled},
		StageConfirmed: {refused, refused, refused, StageDisabled},
		StageDisabled:  {StagePending, refused, refused, refused},
	}
	for _, stage := range stages {
		for i, event := range events {
			t.Run(string(stage)+"/"+string(event), func(t *testing.T) {
				next, err := Next(stage, event)
				if want[stage][i] == refused {
					require.ErrorIs(t, err, ErrNoTransition)
					assert.Equal(t, stage, next)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, want[stage][i], next)
			})
		}
	}
}

func TestApplyCountsEachTransition(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	state := EnrollmentState{Stage: StagePending, Version: 3, CreatedAt: created}

	enrollment := NewEnrollmentID()
	again, err := state.apply(EnrollmentEvent{Kind: EventBegin, At: created.Add(time.Minute), Enrollment: enrollment})
	require.NoError(t, err)
	assert.Equal(t, enrollment, again.Enrollment, "begin names the new enrollment")
	assert.Equal(t, EnrollmentVersion(4), again.Version, "a new secret is a write")
	assert.Equal(t, created.Add(time.Minute), again.CreatedAt, "begin names the new enrollment")

	confirmed, err := state.apply(EnrollmentEvent{Kind: EventConfirm, At: created.Add(time.Hour)})
	require.NoError(t, err)
	assert.Equal(t, created, confirmed.CreatedAt, "confirm keeps the enrollment it confirms")
	require.NotNil(t, confirmed.Cause)

	refused, err := confirmed.apply(EnrollmentEvent{Kind: EventConfirm})
	require.ErrorIs(t, err, ErrNoTransition)
	assert.Equal(t, confirmed, refused)
}
