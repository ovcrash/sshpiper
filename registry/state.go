package registry

import "fmt"

// State is the lifecycle state of an entry.
type State string

const (
	StateDraft      State = "draft"
	StateProbing    State = "probing"
	StateReady      State = "ready"
	StateExposed    State = "exposed"
	StateRetired    State = "retired"
	StateNeedsCheck State = "needs_check"
)

// transitions lists the allowed moves. Retiring is possible from any live
// state; a retired entry can be reactivated back to draft (then probed and
// exposed again).
var transitions = map[State][]State{
	StateDraft:      {StateProbing, StateRetired},
	StateProbing:    {StateReady, StateDraft, StateRetired},
	StateReady:      {StateExposed, StateProbing, StateRetired},
	StateExposed:    {StateNeedsCheck, StateRetired},
	StateNeedsCheck: {StateProbing, StateRetired},
	StateRetired:    {StateDraft},
}

// Valid reports whether s is a known state.
func (s State) Valid() bool {
	_, ok := transitions[s]
	return ok
}

// CanMoveTo reports whether the transition s -> to is allowed.
func (s State) CanMoveTo(to State) bool {
	for _, t := range transitions[s] {
		if t == to {
			return true
		}
	}
	return false
}

// TransitionError is returned for a refused state change.
type TransitionError struct {
	From, To State
}

func (e *TransitionError) Error() string {
	return fmt.Sprintf("registry: transition %s -> %s is not allowed", e.From, e.To)
}

// Servable reports whether the daemon may serve connections for this state
// to anyone. Entries in ready state are served to verification sources only.
func (s State) Servable() bool { return s == StateExposed }
