package notifier

import "context"

// AnalysisCard holds the data for rendering an alert analysis notification.
type AnalysisCard struct {
	Summary          string
	RootCause        string
	Severity         string
	Impact           string
	AffectedServices []string
	MetricInsights   []MetricInsightCard
	Recommendations  []string
	Confidence       float64
	AnalyzedAt       string
	ModelUsed        string
	InputTokens      int
	OutputTokens     int
}

// MetricInsightCard holds a single metric insight for display in a card.
type MetricInsightCard struct {
	MetricName  string
	Trend       string
	Observation string
}

// HealingPlanCard extends AnalysisCard with a healing plan for approval.
type HealingPlanCard struct {
	AnalysisCard
	PlanDescription string
	Commands        []CommandCard
	RollbackSteps   int
	OverallRisk     string
	EstimatedTime   string
	Warnings        []string
	ApprovalID      string
}

// CommandCard holds a single command step for display in a healing plan card.
type CommandCard struct {
	Step        int
	Description string
	CommandType string
	Command     string
	Target      string
	RiskLevel   string
	TimeoutSec  int
}

// ExecutionProgress holds the progress of a healing plan execution.
type ExecutionProgress struct {
	Steps []StepProgress
}

// StepProgress holds the progress of a single execution step.
type StepProgress struct {
	Step    int
	Command string
	Status  string // "pending", "running", "success", "failed", "skipped"
	Error   string
}

// Notifier sends alert analysis and healing plan notifications.
type Notifier interface {
	SendAnalysis(ctx context.Context, card AnalysisCard) (messageID string, err error)
	SendHealingPlan(ctx context.Context, card HealingPlanCard) (messageID string, err error)
	UpdateProgress(ctx context.Context, messageID string, progress ExecutionProgress) error
	SendExecutionComplete(ctx context.Context, messageID string, success bool, summary string) error

	// SendText sends a plain text message to a chat. Returns the message ID.
	SendText(ctx context.Context, chatID, text string) (messageID string, err error)

	// SendReply sends a text message as a reply to an existing message. Returns the new message ID.
	SendReply(ctx context.Context, parentMessageID, text string) (messageID string, err error)

	// SendFeedbackCard asks the user whether the plan worked. Buttons route
	// back through the callback endpoint and write IncidentFeedback records.
	SendFeedbackCard(ctx context.Context, card FeedbackCard) (messageID string, err error)
}

// FeedbackCard solicits 👍 / 👎 / 💬 feedback after a plan completes (or
// after the user closes a healing flow without execution).
type FeedbackCard struct {
	AlertID       string
	ApprovalID    string
	AlertName     string
	OutcomeStatus string // "success", "failed", "manual_resolution"
	Note          string // optional one-line summary
}
