package loginflow

// FlowState is the stage of one login in progress.
type FlowState string

const (
	// StateAwaiting is waiting for a first factor.
	StateAwaiting FlowState = "awaiting"
	// StateAwaitingSecond has one factor and needs one more.
	StateAwaitingSecond FlowState = "awaiting_second"
	// StatePendingLink holds an external account that is not linked yet.
	StatePendingLink FlowState = "pending_link"
	// StateComplete has enough factors. It is final.
	StateComplete FlowState = "complete"
	// StateCancelled was abandoned. It is final.
	StateCancelled FlowState = "cancelled"
)

// Final reports whether the row for this state is deleted.
func (s FlowState) Final() bool {
	return s == StateComplete || s == StateCancelled
}
