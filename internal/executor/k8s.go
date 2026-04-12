package executor

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// K8sExecutor executes kubectl commands against a Kubernetes cluster.
type K8sExecutor struct {
	clusterName       string
	kubeconfigPath    string
	kubeContext       string
	allowedNamespaces map[string]bool
	logger            *slog.Logger
}

// NewK8sExecutor creates a new K8s executor.
// If kubeconfigPath is empty, it assumes in-cluster config (kubectl default behavior).
func NewK8sExecutor(clusterName, kubeconfigPath, kubeContext string, allowedNamespaces []string, logger *slog.Logger) *K8sExecutor {
	nsMap := make(map[string]bool, len(allowedNamespaces))
	for _, ns := range allowedNamespaces {
		nsMap[ns] = true
	}
	return &K8sExecutor{
		clusterName:       clusterName,
		kubeconfigPath:    kubeconfigPath,
		kubeContext:       kubeContext,
		allowedNamespaces: nsMap,
		logger:            logger,
	}
}

func (e *K8sExecutor) Type() CommandType {
	return CommandTypeK8s
}

func (e *K8sExecutor) Execute(ctx context.Context, cmd Command) (*ExecutionResult, error) {
	if err := e.validateNamespace(cmd.Namespace); err != nil {
		return &ExecutionResult{
			CommandID: cmd.ID,
			Success:   false,
			Error:     err.Error(),
		}, err
	}

	start := time.Now()
	args := e.buildArgs(cmd.Command)

	e.logger.Info("executing k8s command",
		"cluster", e.clusterName,
		"command", cmd.Command,
		"namespace", cmd.Namespace,
	)

	c := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	err := c.Run()
	duration := time.Since(start)

	output := truncateOutput(stdout.String(), 10240)
	errStr := truncateOutput(stderr.String(), 10240)

	result := &ExecutionResult{
		CommandID: cmd.ID,
		Duration:  duration,
	}

	if err != nil {
		result.Success = false
		result.Error = errStr
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Output = output
		return result, nil
	}

	result.Success = true
	result.Output = output
	result.ExitCode = 0
	return result, nil
}

func (e *K8sExecutor) DryRun(ctx context.Context, cmd Command) error {
	if err := e.validateNamespace(cmd.Namespace); err != nil {
		return err
	}
	// For dry-run, we just validate the command structure
	args := e.buildArgs(cmd.Command)
	if len(args) == 0 {
		return fmt.Errorf("empty command")
	}
	if args[0] != "kubectl" {
		return fmt.Errorf("k8s executor only supports kubectl commands, got %q", args[0])
	}
	return nil
}

func (e *K8sExecutor) validateNamespace(namespace string) error {
	if len(e.allowedNamespaces) == 0 {
		return nil
	}
	if e.allowedNamespaces["*"] {
		return nil
	}
	if namespace == "" {
		return nil
	}
	if !e.allowedNamespaces[namespace] {
		return fmt.Errorf("namespace %q is not in the allowed list for cluster %q", namespace, e.clusterName)
	}
	return nil
}

func (e *K8sExecutor) buildArgs(command string) []string {
	parts := strings.Fields(command)
	if e.kubeconfigPath != "" {
		parts = append(parts, "--kubeconfig", e.kubeconfigPath)
	}
	if e.kubeContext != "" {
		parts = append(parts, "--context", e.kubeContext)
	}
	return parts
}

func truncateOutput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... [truncated]"
}
