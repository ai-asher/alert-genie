package executor

import "time"

// CommandType identifies the executor backend.
type CommandType string

const (
	CommandTypeK8s CommandType = "k8s"
	CommandTypeSSH CommandType = "ssh"
)

// Command is a validated command ready for execution.
type Command struct {
	ID            string            `json:"id"`
	ApprovalID    string            `json:"approval_id"`
	AlertID       string            `json:"alert_id"`
	Step          int               `json:"step"`
	Type          CommandType       `json:"type"`
	Target        string            `json:"target"`
	Namespace     string            `json:"namespace,omitempty"`
	Command       string            `json:"command"`
	Args          map[string]string `json:"args,omitempty"`
	TimeoutSec    int               `json:"timeout_seconds"`
	VerifyCommand string            `json:"verify_command,omitempty"`
}

// ExecutionResult is the outcome of running a single command.
type ExecutionResult struct {
	CommandID string        `json:"command_id"`
	Success   bool          `json:"success"`
	Output    string        `json:"output"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	ExitCode  int           `json:"exit_code"`
}
