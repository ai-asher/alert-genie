package approval

import "time"

// Status represents the state of an approval request.
type Status string

const (
	StatusPending    Status = "pending"
	StatusApproved   Status = "approved"
	StatusRejected   Status = "rejected"
	StatusModified   Status = "modified"
	StatusExpired    Status = "expired"
	StatusExecuting  Status = "executing"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusSuperseded Status = "superseded"
)

// validTransitions defines the allowed state transitions.
var validTransitions = map[Status][]Status{
	StatusPending:   {StatusApproved, StatusRejected, StatusModified, StatusExpired, StatusSuperseded},
	StatusApproved:  {StatusExecuting},
	StatusModified:  {StatusExecuting},
	StatusExecuting: {StatusCompleted, StatusFailed},
}

// CanTransitionTo checks if a transition from the current status to the target status is valid.
func (s Status) CanTransitionTo(target Status) bool {
	targets, ok := validTransitions[s]
	if !ok {
		return false
	}
	for _, t := range targets {
		if t == target {
			return true
		}
	}
	return false
}

// actionToStatus maps callback actions to approval statuses.
var actionToStatus = map[string]Status{
	"approve": StatusApproved,
	"reject":  StatusRejected,
	"modify":  StatusModified,
}

// StatusFromAction converts a callback action string to the corresponding Status.
// Returns empty string if the action is unknown.
func StatusFromAction(action string) Status {
	s, ok := actionToStatus[action]
	if !ok {
		return ""
	}
	return s
}

// IsFinal returns true if the status represents a terminal state.
func (s Status) IsFinal() bool {
	switch s {
	case StatusRejected, StatusExpired, StatusCompleted, StatusFailed, StatusSuperseded:
		return true
	default:
		return false
	}
}

// Approval represents an approval record in the domain layer.
type Approval struct {
	ID            string
	AlertID       string
	PlanJSON      string
	Status        Status
	RequestedAt   time.Time
	RespondedAt   *time.Time
	ApproverID    string
	ApproverName  string
	Comment       string
	LarkMessageID string
	ExpiresAt     time.Time
}
