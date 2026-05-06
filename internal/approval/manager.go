package approval

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/alert-genie/alert-genie/internal/store"
)

// Manager manages approval lifecycle and state transitions.
type Manager interface {
	// CreateApproval creates a new pending approval request.
	CreateApproval(ctx context.Context, alertID, planJSON, larkMessageID string, ttl time.Duration) (approvalID string, err error)
	// CreateApprovalWithParent creates a new pending approval that supersedes a previous one.
	CreateApprovalWithParent(ctx context.Context, alertID, planJSON, larkMessageID string, ttl time.Duration, parentApprovalID string) (approvalID string, err error)
	// ProcessCallback processes an approval callback (approve/reject/modify).
	ProcessCallback(ctx context.Context, approvalID, action, userID string) error
	// GetPendingApprovals returns all pending approval records.
	GetPendingApprovals(ctx context.Context) ([]*store.ApprovalRecord, error)
	// ExpireStale marks stale pending approvals as expired and returns the count.
	ExpireStale(ctx context.Context) (int, error)
}

type manager struct {
	st     store.Store
	logger *slog.Logger
}

// NewManager creates a new approval Manager backed by the given store.
func NewManager(st store.Store, logger *slog.Logger) Manager {
	return &manager{
		st:     st,
		logger: logger,
	}
}

// CreateApproval creates a new pending approval and persists it.
func (m *manager) CreateApproval(ctx context.Context, alertID, planJSON, larkMessageID string, ttl time.Duration) (string, error) {
	return m.CreateApprovalWithParent(ctx, alertID, planJSON, larkMessageID, ttl, "")
}

// CreateApprovalWithParent creates a new pending approval that may supersede a previous one.
func (m *manager) CreateApprovalWithParent(ctx context.Context, alertID, planJSON, larkMessageID string, ttl time.Duration, parentApprovalID string) (string, error) {
	id, err := generateUUID()
	if err != nil {
		return "", fmt.Errorf("generate approval ID: %w", err)
	}

	now := time.Now()
	record := &store.ApprovalRecord{
		ID:               id,
		AlertID:          alertID,
		PlanJSON:         planJSON,
		Status:           string(StatusPending),
		RequestedAt:      now,
		LarkMessageID:    larkMessageID,
		ExpiresAt:        now.Add(ttl),
		ParentApprovalID: parentApprovalID,
	}

	if err := m.st.SaveApproval(ctx, record); err != nil {
		return "", fmt.Errorf("save approval: %w", err)
	}

	m.logger.Info("approval created",
		slog.String("approval_id", id),
		slog.String("alert_id", alertID),
		slog.String("parent_approval_id", parentApprovalID),
		slog.Time("expires_at", record.ExpiresAt),
	)

	return id, nil
}

// ProcessCallback validates and applies a callback action to an approval.
func (m *manager) ProcessCallback(ctx context.Context, approvalID, action, userID string) error {
	record, err := m.st.GetApproval(ctx, approvalID)
	if err != nil {
		return fmt.Errorf("get approval: %w", err)
	}
	if record == nil {
		return fmt.Errorf("approval %s not found", approvalID)
	}

	currentStatus := Status(record.Status)
	targetStatus := StatusFromAction(action)
	if targetStatus == "" {
		return fmt.Errorf("unknown action: %s", action)
	}

	// Friendly errors for known terminal states so the callback handler can
	// surface them as Lark toasts rather than "invalid transition".
	switch currentStatus {
	case StatusSuperseded:
		return fmt.Errorf("this plan has been superseded by a newer version — please act on the latest plan card")
	case StatusExpired:
		return fmt.Errorf("this approval has expired (TTL exceeded) — re-trigger the alert to get a fresh plan")
	case StatusApproved, StatusExecuting, StatusCompleted, StatusFailed:
		return fmt.Errorf("this plan is already %s and cannot be re-acted upon", currentStatus)
	case StatusRejected:
		return fmt.Errorf("this plan was already rejected")
	}

	// Validate state transition
	if !currentStatus.CanTransitionTo(targetStatus) {
		return fmt.Errorf("invalid transition from %s to %s", currentStatus, targetStatus)
	}

	// Check if the approval has expired
	if time.Now().After(record.ExpiresAt) && currentStatus == StatusPending {
		// Auto-expire it
		if err := m.st.UpdateApprovalStatus(ctx, approvalID, string(StatusExpired), "", "auto-expired"); err != nil {
			return fmt.Errorf("expire approval: %w", err)
		}
		return fmt.Errorf("approval %s has expired", approvalID)
	}

	if err := m.st.UpdateApprovalStatus(ctx, approvalID, string(targetStatus), userID, ""); err != nil {
		return fmt.Errorf("update approval status: %w", err)
	}

	m.logger.Info("approval callback processed",
		slog.String("approval_id", approvalID),
		slog.String("action", action),
		slog.String("user_id", userID),
		slog.String("new_status", string(targetStatus)),
	)

	return nil
}

// GetPendingApprovals returns all approvals with status "pending".
func (m *manager) GetPendingApprovals(ctx context.Context) ([]*store.ApprovalRecord, error) {
	status := string(StatusPending)
	return m.st.ListApprovals(ctx, store.ApprovalFilter{
		Status: &status,
		Limit:  100,
	})
}

// ExpireStale finds pending approvals past their expiry time and marks them expired.
func (m *manager) ExpireStale(ctx context.Context) (int, error) {
	pending, err := m.GetPendingApprovals(ctx)
	if err != nil {
		return 0, fmt.Errorf("list pending approvals: %w", err)
	}

	now := time.Now()
	expired := 0
	for _, record := range pending {
		if now.After(record.ExpiresAt) {
			if err := m.st.UpdateApprovalStatus(ctx, record.ID, string(StatusExpired), "", "auto-expired by stale check"); err != nil {
				m.logger.Error("failed to expire approval",
					slog.String("approval_id", record.ID),
					slog.Any("error", err),
				)
				continue
			}
			expired++
			m.logger.Info("approval expired",
				slog.String("approval_id", record.ID),
				slog.String("alert_id", record.AlertID),
			)
		}
	}

	return expired, nil
}

// generateUUID generates a random UUID v4.
func generateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	// Set version 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant 10
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16]), nil
}
