package totp

import "time"

// EnrollmentStage is the step of the TOTP enrollment of one user.
type EnrollmentStage string

const (
	// StageNone has no credential row.
	StageNone EnrollmentStage = "none"
	// StagePending has a secret that waits for its first code.
	StagePending EnrollmentStage = "pending"
	// StageConfirmed has two-step login on.
	StageConfirmed EnrollmentStage = "confirmed"
	// StageDisabled was turned off. Like StageNone, it has no row, so a load reads StageNone.
	StageDisabled EnrollmentStage = "disabled"
)

// Stored reports whether a credential row holds this stage.
func (s EnrollmentStage) Stored() bool {
	return s == StagePending || s == StageConfirmed
}

// EnrollmentEventKind is one input to the enrollment policy.
type EnrollmentEventKind string

const (
	// EventBegin makes a new secret.
	EventBegin EnrollmentEventKind = "begin"
	// EventConfirm records the first matching code.
	EventConfirm EnrollmentEventKind = "confirm"
	// EventExpire ends a pending enrollment older than EnrollmentTTL.
	EventExpire EnrollmentEventKind = "expire"
	// EventDisable turns two-step login off.
	EventDisable EnrollmentEventKind = "disable"
)

// enrollmentPolicy is every allowed transition. A missing pair is ErrNoTransition.
var enrollmentPolicy = map[EnrollmentStage]map[EnrollmentEventKind]EnrollmentStage{
	StageNone:      {EventBegin: StagePending},
	StagePending:   {EventBegin: StagePending, EventConfirm: StageConfirmed, EventExpire: StageNone, EventDisable: StageDisabled},
	StageConfirmed: {EventDisable: StageDisabled},
	StageDisabled:  {EventBegin: StagePending},
}

// Next reads no clock and no store: the service checks expiry and codes before it sends an event.
func Next(stage EnrollmentStage, event EnrollmentEventKind) (EnrollmentStage, error) {
	next, ok := enrollmentPolicy[stage][event]
	if !ok {
		return stage, ErrNoTransition
	}
	return next, nil
}

// EnrollmentVersion counts the transitions of one credential row.
// A write MUST name the version it read, so two requests that read the same row cannot both move it.
type EnrollmentVersion int64

// EnrollmentEvent is one input with the data its write stores.
// At is the created time for EventBegin and the confirmed time for EventConfirm.
// Sealed and Enrollment are set for EventBegin. Step and RecoveryCodes are set for EventConfirm.
type EnrollmentEvent struct {
	Kind          EnrollmentEventKind
	At            time.Time
	Sealed        SealedSecret
	Enrollment    EnrollmentID
	Step          TimeStep
	RecoveryCodes []RecoveryHash
}

// EnrollmentState is the state of the enrollment machine of one user.
// Enrollment names the stored enrollment: a write changes only the row of that enrollment.
// Cause is the event that made this state, for the store to write. A loaded state has none.
type EnrollmentState struct {
	Stage      EnrollmentStage
	Version    EnrollmentVersion
	CreatedAt  time.Time
	Enrollment EnrollmentID
	Cause      *EnrollmentEvent
}

// apply runs Next and adds the data of event. Each allowed event is one write, so the version increases.
func (s EnrollmentState) apply(event EnrollmentEvent) (EnrollmentState, error) {
	stage, err := Next(s.Stage, event.Kind)
	if err != nil {
		return s, err
	}
	next := EnrollmentState{Stage: stage, Version: s.Version + 1, CreatedAt: s.CreatedAt, Enrollment: s.Enrollment, Cause: &event}
	if event.Kind == EventBegin {
		next.CreatedAt = event.At
		next.Enrollment = event.Enrollment
	}
	return next, nil
}
