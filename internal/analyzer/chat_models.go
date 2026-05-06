package analyzer

import "time"

// ChatMessage represents a single turn in a multi-turn conversation between
// the user and the assistant about a previously analyzed alert.
type ChatMessage struct {
	// Role is either "user" or "assistant" (matching the Anthropic Messages API roles).
	Role string
	// Content is the raw text of the message.
	Content string
}

// ChatRequest is the input to the Analyzer.Chat method. It carries the full
// background context (the original alert + initial analysis + healing plan),
// any prior conversation turns, and the latest user message to respond to.
type ChatRequest struct {
	// OriginalAnalysis is the original AnalysisResult produced by Analyze.
	// It includes the alert summary, root cause, recommendations and (optionally)
	// the healing plan. It is serialized into the system prompt so the LLM has
	// the full background for every chat turn.
	OriginalAnalysis *AnalysisResult

	// OriginalAlert is a human-readable summary of the alert (alert name,
	// labels, key annotations) that triggered the original analysis. Embedded
	// in the system prompt for additional context.
	OriginalAlert string

	// History is the prior chat messages in chronological order (oldest first).
	// It does NOT include the current UserMessage. These are passed as messages[]
	// to the Anthropic API rather than being inlined in the system prompt.
	History []ChatMessage

	// UserMessage is the current user message (latest @Bot message) that the
	// assistant should respond to.
	UserMessage string

	// UserName is the optional display name of the user, used by the LLM to
	// address them by name when appropriate.
	UserName string
}

// ChatResponseType indicates whether the LLM produced a plain text reply or
// a revised healing plan.
type ChatResponseType string

const (
	// ChatResponseText means the LLM returned a plain text reply (an explanation,
	// clarification, or follow-up question).
	ChatResponseText ChatResponseType = "text"
	// ChatResponseRevisedPlan means the LLM produced a revised healing plan in
	// response to a user request to modify the original plan.
	ChatResponseRevisedPlan ChatResponseType = "revised_plan"
)

// ChatResponse is the structured output from the Analyzer.Chat method. The
// shape matches the JSON object the LLM is instructed to produce.
type ChatResponse struct {
	// Type is either "text" or "revised_plan".
	Type ChatResponseType `json:"type"`
	// TextContent is the plain text reply when Type == ChatResponseText.
	TextContent string `json:"text_content,omitempty"`
	// RevisedPlan is the new healing plan when Type == ChatResponseRevisedPlan.
	// It uses the same schema as HealingPlan in the original analysis.
	RevisedPlan *HealingPlan `json:"revised_plan,omitempty"`
	// Summary is a short user-facing summary describing the change or reply
	// (e.g. "explained why kubectl_scale was chosen" or
	// "Revised plan: switched from rollout_restart to scale to=0 then to=N").
	Summary string `json:"summary,omitempty"`
	// AnalyzedAt is the timestamp at which the chat response was produced.
	AnalyzedAt time.Time `json:"analyzed_at"`
	// ModelUsed is the model identifier returned by the API.
	ModelUsed string `json:"model_used"`
	// TokensUsed reports input/output token consumption for this chat turn.
	TokensUsed TokenUsage `json:"tokens_used"`
}
