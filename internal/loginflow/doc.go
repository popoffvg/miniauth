// Package loginflow is the login in progress.
// A step reports an event. The policy in LoginFlow.Next decides the next state.
// A session starts only after the flow reaches a final state, and that work is outside this package.
package loginflow
