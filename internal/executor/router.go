package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/alert-genie/alert-genie/internal/notifier"
	"github.com/alert-genie/alert-genie/internal/store"
)

// Router routes commands to the correct executor and orchestrates plan execution.
type Router struct {
	executors map[CommandType]Executor
	store     store.Store
	notifier  notifier.Notifier
	logger    *slog.Logger
}

func NewRouter(executors map[CommandType]Executor, st store.Store, n notifier.Notifier, logger *slog.Logger) *Router {
	return &Router{
		executors: executors,
		store:     st,
		notifier:  n,
		logger:    logger,
	}
}

// HealingPlanJSON matches the JSON structure stored in approvals.plan_json.
type HealingPlanJSON struct {
	Commands     []HealingCommandJSON `json:"commands"`
	RollbackPlan []HealingCommandJSON `json:"rollback_plan"`
}

type HealingCommandJSON struct {
	Step          int    `json:"step"`
	Description   string `json:"description"`
	CommandType   string `json:"command_type"`
	Target        string `json:"target"`
	Namespace     string `json:"namespace,omitempty"`
	Command       string `json:"command"`
	RiskLevel     string `json:"risk_level"`
	ImpactSummary string `json:"impact_summary"`
	TimeoutSec    int    `json:"timeout_seconds"`
	WaitAfterSec  int    `json:"wait_after_seconds"`
	VerifyCommand string `json:"verify_command,omitempty"`
}

// ExecutePlan runs all commands in a healing plan sequentially.
func (r *Router) ExecutePlan(ctx context.Context, approval *store.ApprovalRecord) {
	var plan HealingPlanJSON
	if err := json.Unmarshal([]byte(approval.PlanJSON), &plan); err != nil {
		r.logger.Error("failed to parse healing plan", "error", err, "approval_id", approval.ID)
		return
	}

	r.logger.Info("starting plan execution",
		"approval_id", approval.ID,
		"steps", len(plan.Commands),
	)

	// Update approval status to executing
	r.store.UpdateApprovalStatus(ctx, approval.ID, "executing", "system", "")

	steps := make([]notifier.StepProgress, len(plan.Commands))
	for i, cmd := range plan.Commands {
		steps[i] = notifier.StepProgress{
			Step:    cmd.Step,
			Command: cmd.Command,
			Status:  "pending",
		}
	}

	for i, cmd := range plan.Commands {
		// Update progress: current step running
		steps[i].Status = "running"
		r.notifier.UpdateProgress(ctx, approval.LarkMessageID, notifier.ExecutionProgress{Steps: steps})

		exec, ok := r.executors[CommandType(cmd.CommandType)]
		if !ok {
			errMsg := fmt.Sprintf("unknown command type: %s", cmd.CommandType)
			steps[i].Status = "failed"
			steps[i].Error = errMsg
			r.recordStep(ctx, approval, cmd, "failed", "", errMsg)
			r.notifier.UpdateProgress(ctx, approval.LarkMessageID, notifier.ExecutionProgress{Steps: steps})
			r.failPlan(ctx, approval, steps, cmd.Step)
			return
		}

		timeout := time.Duration(cmd.TimeoutSec) * time.Second
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		cmdCtx, cancel := context.WithTimeout(ctx, timeout)

		execCmd := Command{
			ID:            fmt.Sprintf("%s-step-%d", approval.ID, cmd.Step),
			ApprovalID:    approval.ID,
			AlertID:       approval.AlertID,
			Step:          cmd.Step,
			Type:          CommandType(cmd.CommandType),
			Target:        cmd.Target,
			Namespace:     cmd.Namespace,
			Command:       cmd.Command,
			TimeoutSec:    cmd.TimeoutSec,
			VerifyCommand: cmd.VerifyCommand,
		}

		result, err := exec.Execute(cmdCtx, execCmd)
		cancel()

		if err != nil || (result != nil && !result.Success) {
			errMsg := ""
			output := ""
			if result != nil {
				errMsg = result.Error
				output = result.Output
			}
			if err != nil {
				errMsg = err.Error()
			}
			steps[i].Status = "failed"
			steps[i].Error = errMsg
			r.recordStep(ctx, approval, cmd, "failed", output, errMsg)
			r.notifier.UpdateProgress(ctx, approval.LarkMessageID, notifier.ExecutionProgress{Steps: steps})
			r.failPlan(ctx, approval, steps, cmd.Step)
			return
		}

		steps[i].Status = "success"
		r.recordStep(ctx, approval, cmd, "success", result.Output, "")
		r.notifier.UpdateProgress(ctx, approval.LarkMessageID, notifier.ExecutionProgress{Steps: steps})

		// Wait between steps if configured
		if cmd.WaitAfterSec > 0 {
			select {
			case <-time.After(time.Duration(cmd.WaitAfterSec) * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}

	// All steps succeeded
	r.store.UpdateApprovalStatus(ctx, approval.ID, "completed", "system", "all steps executed successfully")
	r.notifier.SendExecutionComplete(ctx, approval.LarkMessageID, true, "All healing steps completed successfully")

	r.logger.Info("plan execution completed", "approval_id", approval.ID)
}

func (r *Router) recordStep(ctx context.Context, approval *store.ApprovalRecord, cmd HealingCommandJSON, status, output, errMsg string) {
	now := time.Now()
	log := &store.ExecutionLog{
		ID:          fmt.Sprintf("%s-step-%d", approval.ID, cmd.Step),
		ApprovalID:  approval.ID,
		AlertID:     approval.AlertID,
		Step:        cmd.Step,
		CommandType: cmd.CommandType,
		Target:      cmd.Target,
		Command:     cmd.Command,
		Status:      status,
		Output:      output,
		Error:       errMsg,
		StartedAt:   now,
		FinishedAt:  &now,
		ExecutedBy:  "system",
	}
	if err := r.store.SaveExecutionLog(ctx, log); err != nil {
		r.logger.Error("failed to save execution log", "error", err)
	}
}

func (r *Router) failPlan(ctx context.Context, approval *store.ApprovalRecord, steps []notifier.StepProgress, failedStep int) {
	// Mark remaining steps as skipped
	for i := range steps {
		if steps[i].Status == "pending" {
			steps[i].Status = "skipped"
		}
	}

	r.store.UpdateApprovalStatus(ctx, approval.ID, "failed", "system",
		fmt.Sprintf("failed at step %d", failedStep))
	r.notifier.SendExecutionComplete(ctx, approval.LarkMessageID, false,
		fmt.Sprintf("Execution failed at step %d. Review logs and consider rollback.", failedStep))

	r.logger.Error("plan execution failed",
		"approval_id", approval.ID,
		"failed_step", failedStep,
	)
}
