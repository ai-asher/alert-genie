package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// CallbackHandler handles Lark card button callbacks.
type CallbackHandler struct {
	verificationToken string
	ProcessFunc       func(ctx context.Context, approvalID, action, userID string) error
}

// NewCallbackHandler creates a new CallbackHandler.
func NewCallbackHandler(verificationToken string, processFunc func(ctx context.Context, approvalID, action, userID string) error) *CallbackHandler {
	return &CallbackHandler{
		verificationToken: verificationToken,
		ProcessFunc:       processFunc,
	}
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
	approvalID := req.Action.Value["approval_id"]

	if action == "" || approvalID == "" {
		http.Error(w, "missing action or approval_id", http.StatusBadRequest)
		return
	}

	// Process the callback
	if err := h.ProcessFunc(r.Context(), approvalID, action, req.OpenID); err != nil {
		// Return a toast with error
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]any{
			"toast": map[string]any{
				"type":    "error",
				"content": fmt.Sprintf("Failed to process: %v", err),
			},
		})
		w.Write(resp)
		return
	}

	// Return a success toast
	w.Header().Set("Content-Type", "application/json")
	toastContent := "Action processed successfully"
	switch action {
	case "approve":
		toastContent = "Plan approved. Execution will begin shortly."
	case "reject":
		toastContent = "Plan rejected."
	case "modify":
		toastContent = "Plan approved with modifications."
	}
	resp, _ := json.Marshal(map[string]any{
		"toast": map[string]any{
			"type":    "success",
			"content": toastContent,
		},
	})
	w.Write(resp)
}
