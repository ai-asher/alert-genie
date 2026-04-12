package executor

import "context"

// Executor runs validated commands against a target system.
type Executor interface {
	// Type returns the command type this executor handles.
	Type() CommandType

	// Execute runs a single command and returns the result.
	// The command MUST have already passed safety validation.
	Execute(ctx context.Context, cmd Command) (*ExecutionResult, error)

	// DryRun validates that the command could execute without actually running it.
	DryRun(ctx context.Context, cmd Command) error
}
