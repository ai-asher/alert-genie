// Package chat orchestrates multi-turn conversations between users and the LLM
// triggered by @Bot mentions in Lark group chats. It links inbound chat events
// to existing alerts/approvals via thread root_message_id, fetches conversation
// history from the store, calls the analyzer's Chat method, and either replies
// with text or generates a revised healing plan.
package chat

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/alert-genie/alert-genie/internal/analyzer"
	"github.com/alert-genie/alert-genie/internal/approval"
	"github.com/alert-genie/alert-genie/internal/notifier"
	"github.com/alert-genie/alert-genie/internal/safety"
	"github.com/alert-genie/alert-genie/internal/store"
)

// Orchestrator handles inbound chat events.
type Orchestrator struct {
	store       store.Store
	analyzer    analyzer.Analyzer
	notifier    notifier.Notifier
	approval    approval.Manager
	safety      safety.Validator
	approvalTTL time.Duration
	logger      *slog.Logger
}

// New creates a new chat Orchestrator.
func New(
	st store.Store,
	az analyzer.Analyzer,
	n notifier.Notifier,
	am approval.Manager,
	sv safety.Validator,
	approvalTTL time.Duration,
	logger *slog.Logger,
) *Orchestrator {
	return &Orchestrator{
		store:       st,
		analyzer:    az,
		notifier:    n,
		approval:    am,
		safety:      sv,
		approvalTTL: approvalTTL,
		logger:      logger,
	}
}

// HandleEvent is the entry point for inbound Lark chat events.
// It is wired into the notifier.EventHandler.ProcessFunc.
func (o *Orchestrator) HandleEvent(ctx context.Context, ev notifier.ChatEvent) error {
	if !ev.MentionedBot {
		return nil // ignore messages that don't mention the bot
	}
	if ev.Text == "" {
		return nil
	}

	// 1. Locate the conversation: try root_message_id (thread reply on the original card),
	//    then parent_message_id (reply to a bot reply).
	conv, err := o.findConversation(ctx, ev)
	if err != nil {
		o.logger.Error("find conversation failed", "error", err, "event_id", ev.EventID)
		return err
	}
	if conv == nil {
		// No matching conversation — user mentioned the bot in an unrelated context.
		// Send a help reply.
		_, _ = o.notifier.SendReply(ctx, ev.MessageID,
			"找不到相关告警上下文。请在告警卡片下回复 @Bot 来提问或修改方案。")
		return nil
	}

	// 2. Persist the user message
	userMsg := &store.Message{
		ID:              generateID(),
		ConversationID:  conv.ID,
		Role:            "user",
		Content:         ev.Text,
		LarkMessageID:   ev.MessageID,
		ParentLarkMsgID: ev.ParentMessageID,
		UserOpenID:      ev.SenderOpenID,
		UserName:        ev.SenderName,
		CreatedAt:       ev.CreatedAt,
	}
	if userMsg.CreatedAt.IsZero() {
		userMsg.CreatedAt = time.Now()
	}
	if err := o.store.SaveMessage(ctx, userMsg); err != nil {
		o.logger.Error("save user message failed", "error", err)
	}

	// 3. Fetch original analysis + history
	originalAnalysis, originalAlertText, err := o.loadOriginalContext(ctx, conv)
	if err != nil {
		o.logger.Error("load original context failed", "error", err)
		_, _ = o.notifier.SendReply(ctx, ev.MessageID, "无法加载告警原始分析，请稍后再试。")
		return err
	}

	history, err := o.buildHistory(ctx, conv.ID, ev.MessageID)
	if err != nil {
		o.logger.Warn("build history failed, continuing without it", "error", err)
	}

	// 4. Call the analyzer's Chat method
	chatReq := analyzer.ChatRequest{
		OriginalAnalysis: originalAnalysis,
		OriginalAlert:    originalAlertText,
		History:          history,
		UserMessage:      ev.Text,
		UserName:         ev.SenderName,
	}

	resp, err := o.analyzer.Chat(ctx, chatReq)
	if err != nil {
		o.logger.Error("analyzer chat failed", "error", err)
		_, _ = o.notifier.SendReply(ctx, ev.MessageID, fmt.Sprintf("AI 分析出错：%v", err))
		return err
	}

	// 5. Branch: text reply vs revised plan
	switch resp.Type {
	case analyzer.ChatResponseText:
		return o.handleTextReply(ctx, conv, ev, resp)
	case analyzer.ChatResponseRevisedPlan:
		return o.handleRevisedPlan(ctx, conv, ev, resp)
	default:
		o.logger.Warn("unknown chat response type", "type", resp.Type)
		return nil
	}
}

// findConversation locates an existing conversation for the event.
func (o *Orchestrator) findConversation(ctx context.Context, ev notifier.ChatEvent) (*store.Conversation, error) {
	// Try root_message_id first (the original card)
	if ev.RootMessageID != "" {
		conv, err := o.store.GetConversationByRootMessage(ctx, ev.RootMessageID)
		if err != nil {
			return nil, err
		}
		if conv != nil {
			return conv, nil
		}
	}

	// Fall back: parent message might itself be a stored message that points to a conversation
	if ev.ParentMessageID != "" {
		msg, err := o.store.GetMessageByLarkID(ctx, ev.ParentMessageID)
		if err != nil {
			return nil, err
		}
		if msg != nil {
			return o.store.GetConversation(ctx, msg.ConversationID)
		}
	}

	return nil, nil
}

// loadOriginalContext fetches the latest analysis and a brief alert summary.
func (o *Orchestrator) loadOriginalContext(ctx context.Context, conv *store.Conversation) (*analyzer.AnalysisResult, string, error) {
	analysisRec, err := o.store.GetAnalysis(ctx, conv.AlertID)
	if err != nil {
		return nil, "", fmt.Errorf("get analysis: %w", err)
	}
	if analysisRec == nil {
		return nil, "", fmt.Errorf("no analysis found for alert %s", conv.AlertID)
	}

	var result analyzer.AnalysisResult
	if err := json.Unmarshal([]byte(analysisRec.ResultJSON), &result); err != nil {
		return nil, "", fmt.Errorf("unmarshal analysis: %w", err)
	}

	// Build a brief alert summary
	alertRec, _ := o.store.GetAlert(ctx, conv.AlertID)
	var alertText string
	if alertRec != nil {
		alertText = fmt.Sprintf("Alert: %s | Severity: %s | Started: %s",
			alertRec.AlertName, alertRec.Severity, alertRec.StartsAt.Format(time.RFC3339))
	}

	return &result, alertText, nil
}

// buildHistory fetches prior messages, excluding the current user message.
func (o *Orchestrator) buildHistory(ctx context.Context, conversationID, currentMessageID string) ([]analyzer.ChatMessage, error) {
	msgs, err := o.store.ListMessages(ctx, conversationID, 50)
	if err != nil {
		return nil, err
	}
	history := make([]analyzer.ChatMessage, 0, len(msgs))
	for _, m := range msgs {
		if m.LarkMessageID == currentMessageID {
			continue // exclude the just-saved user message; it goes as the latest UserMessage
		}
		history = append(history, analyzer.ChatMessage{
			Role:    m.Role,
			Content: m.Content,
		})
	}
	return history, nil
}

// handleTextReply sends a plain text reply and persists it.
func (o *Orchestrator) handleTextReply(ctx context.Context, conv *store.Conversation, ev notifier.ChatEvent, resp *analyzer.ChatResponse) error {
	text := resp.TextContent
	if text == "" {
		text = "(empty response)"
	}

	replyMsgID, err := o.notifier.SendReply(ctx, ev.MessageID, text)
	if err != nil {
		o.logger.Error("send reply failed", "error", err)
		return err
	}

	// Persist the bot reply
	botMsg := &store.Message{
		ID:              generateID(),
		ConversationID:  conv.ID,
		Role:            "assistant",
		Content:         text,
		LarkMessageID:   replyMsgID,
		ParentLarkMsgID: ev.MessageID,
		CreatedAt:       time.Now(),
	}
	if err := o.store.SaveMessage(ctx, botMsg); err != nil {
		o.logger.Error("save bot reply failed", "error", err)
	}

	o.logger.Info("text reply sent",
		"conversation_id", conv.ID,
		"reply_message_id", replyMsgID,
	)
	return nil
}

// handleRevisedPlan validates the new plan, sends a new healing plan card, and creates a new approval.
func (o *Orchestrator) handleRevisedPlan(ctx context.Context, conv *store.Conversation, ev notifier.ChatEvent, resp *analyzer.ChatResponse) error {
	if resp.RevisedPlan == nil {
		_, _ = o.notifier.SendReply(ctx, ev.MessageID, "AI 表示要修改方案，但未生成有效的方案内容。")
		return fmt.Errorf("revised_plan type but RevisedPlan is nil")
	}
	plan := resp.RevisedPlan

	// Run safety validation on each command in the revised plan
	allSafe := true
	for i, cmd := range plan.Commands {
		verdict, err := o.safety.Validate(ctx, safety.Command{
			Raw:         cmd.Command,
			CommandType: cmd.CommandType,
			Target:      cmd.Target,
			Namespace:   cmd.Namespace,
		})
		if err != nil || !verdict.Allowed {
			reason := "unknown"
			if verdict != nil {
				reason = verdict.Reason
			}
			plan.Commands[i].Description += " [BLOCKED: " + reason + "]"
			allSafe = false
		}
	}
	if !allSafe {
		plan.Warnings = append(plan.Warnings,
			"One or more commands in the revised plan were blocked by the safety system.")
	}

	// Build the healing card. We need the original AnalysisResult fields for the card header.
	originalAnalysis, _, err := o.loadOriginalContext(ctx, conv)
	if err != nil {
		o.logger.Error("reload analysis for revised plan card failed", "error", err)
		return err
	}
	revisedAnalysis := *originalAnalysis
	revisedAnalysis.HealingPlan = plan
	if resp.Summary != "" {
		revisedAnalysis.Summary = "[Revised] " + resp.Summary
	} else {
		revisedAnalysis.Summary = "[Revised] " + originalAnalysis.Summary
	}

	card := buildAnalysisCardFromResult(&revisedAnalysis)
	healingCard := buildHealingPlanCardFromResult(&revisedAnalysis, card)

	msgID, err := o.notifier.SendHealingPlan(ctx, healingCard)
	if err != nil {
		o.logger.Error("send revised healing plan failed", "error", err)
		return err
	}

	// Create new approval, supersede the previous one
	planJSON, _ := json.Marshal(plan)
	parentApprovalID := conv.ApprovalID
	approvalID, err := o.approval.CreateApprovalWithParent(ctx,
		conv.AlertID, string(planJSON), msgID, o.approvalTTL, parentApprovalID)
	if err != nil {
		o.logger.Error("create revised approval failed", "error", err)
	} else {
		// Mark old approval as superseded (if it was still pending)
		if parentApprovalID != "" {
			if old, err := o.store.GetApproval(ctx, parentApprovalID); err == nil && old != nil && old.Status == "pending" {
				_ = o.store.UpdateApprovalStatus(ctx, parentApprovalID, "superseded", "system",
					"superseded by revised plan "+approvalID)
			}
		}
		// Update conversation to point at the new approval
		_ = o.store.UpdateConversationApproval(ctx, conv.ID, approvalID)
	}

	// Persist the bot's revised plan as an assistant message in the conversation
	planSummary := resp.Summary
	if planSummary == "" {
		planSummary = "Revised healing plan generated."
	}
	botMsg := &store.Message{
		ID:              generateID(),
		ConversationID:  conv.ID,
		Role:            "assistant",
		Content:         planSummary,
		LarkMessageID:   msgID,
		ParentLarkMsgID: ev.MessageID,
		CreatedAt:       time.Now(),
	}
	if err := o.store.SaveMessage(ctx, botMsg); err != nil {
		o.logger.Error("save revised plan message failed", "error", err)
	}

	o.logger.Info("revised plan sent",
		"conversation_id", conv.ID,
		"new_approval_id", approvalID,
		"parent_approval_id", parentApprovalID,
		"commands", len(plan.Commands),
	)
	return nil
}

func generateID() string {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		return fmt.Sprintf("err-%d", time.Now().UnixNano())
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
