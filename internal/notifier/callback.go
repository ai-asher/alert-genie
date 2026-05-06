package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ApprovalCallback is invoked for approve/reject/modify button presses on
// healing plan cards.
type ApprovalCallback func(ctx context.Context, approvalID, action, userID string) error

// FeedbackCallback is invoked for the feedback card buttons (👍/👎/💬).
// The values map carries alert_id and approval_id (approval_id may be empty
// when feedback is solicited without a healing execution).
type FeedbackCallback func(ctx context.Context, alertID, approvalID, action, userID string) error

// CallbackHandler handles Lark card button callbacks. Single endpoint, dispatches
// by action prefix: "feedback_*" → FeedbackProcessFunc, others → ApprovalProcessFunc.
type CallbackHandler struct {
	verificationToken   string
	ApprovalProcessFunc ApprovalCallback
	FeedbackProcessFunc FeedbackCallback
}

// NewCallbackHandler creates a new CallbackHandler.
// feedbackProcessFunc may be nil if feedback collection is disabled.
func NewCallbackHandler(verificationToken string, approvalProcessFunc ApprovalCallback) *CallbackHandler {
	return &CallbackHandler{
		verificationToken:   verificationToken,
		ApprovalProcessFunc: approvalProcessFunc,
	}
}

// SetFeedbackHandler attaches the feedback callback. Optional.
func (h *CallbackHandler) SetFeedbackHandler(fn FeedbackCallback) {
	h.FeedbackProcessFunc = fn
}

// callbackRequest represents the JSON body from a Lark card action callback.
type callbackRequest struct {
	Token  string `json:"token"`
	OpenID string `json:"open_id"`
	Action struct {
		Value map[string]string `json:"value"`
	} `json:"action"`
	// Challenge is used for Lark URL verification.
	Challenge string `json:"challenge"`
	Type      string `json:"type"`
}

// HandleCallback processes a Lark card button callback HTTP request.
func (h *CallbackHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req callbackRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Handle Lark URL verification challenge
	if req.Type == "url_verification" {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]string{
			"challenge": req.Challenge,
		})
		w.Write(resp)
		return
	}

	// Verify token
	if req.Token != h.verificationToken {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	action := req.Action.Value["action"]
	if action == "" {
		http.Error(w, "missing action", http.StatusBadRequest)
		return
	}

	// Dispatch by action prefix
	if strings.HasPrefix(action, "feedback_") {
		h.handleFeedback(w, r, req, action)
		return
	}
	h.handleApproval(w, r, req, action)
}

func (h *CallbackHandler) handleApproval(w http.ResponseWriter, r *http.Request, req callbackRequest, action string) {
	approvalID := req.Action.Value["approval_id"]
	if approvalID == "" {
		http.Error(w, "missing approval_id", http.StatusBadRequest)
		return
	}

	if h.ApprovalProcessFunc == nil {
		respondToast(w, "warning", "Approvals are not configured")
		return
	}

	if err := h.ApprovalProcessFunc(r.Context(), approvalID, action, req.OpenID); err != nil {
		respondToast(w, "error", fmt.Sprintf("Failed to process: %v", err))
		return
	}

	toastContent := "Action processed successfully"
	switch action {
	case "approve":
		toastContent = "Plan approved. Execution will begin shortly."
	case "reject":
		toastContent = "Plan rejected."
	case "modify":
		toastContent = "Plan approved with modifications."
	}
	respondToast(w, "success", toastContent)
}

func (h *CallbackHandler) handleFeedback(w http.ResponseWriter, r *http.Request, req callbackRequest, action string) {
	alertID := req.Action.Value["alert_id"]
	approvalID := req.Action.Value["approval_id"] // may be empty
	if alertID == "" {
		http.Error(w, "missing alert_id for feedback", http.StatusBadRequest)
		return
	}

	if h.FeedbackProcessFunc == nil {
		respondToast(w, "warning", "Feedback collection is not enabled")
		return
	}

	if err := h.FeedbackProcessFunc(r.Context(), alertID, approvalID, action, req.OpenID); err != nil {
		respondToast(w, "error", fmt.Sprintf("Failed to record feedback: %v", err))
		return
	}

	toastContent := "Thanks for the feedback!"
	switch action {
	case "feedback_thumbs_up":
		toastContent = "👍 Logged. This will boost similar past plans for future alerts."
	case "feedback_thumbs_down":
		toastContent = "👎 Logged. We'll avoid this approach for similar future alerts."
	case "feedback_comment":
		toastContent = "💬 Reply in this thread to leave a comment — Alert-Genie will pick it up."
	}
	respondToast(w, "success", toastContent)
}

func respondToast(w http.ResponseWriter, typ, content string) {
	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]any{
		"toast": map[string]any{
			"type":    typ,
			"content": content,
		},
	})
	w.Write(resp)
}
