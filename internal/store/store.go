package store

import (
	"context"
	"time"
)

type AlertRecord struct {
	ID          string     `db:"id"`
	Fingerprint string     `db:"fingerprint"`
	AlertName   string     `db:"alert_name"`
	Status      string     `db:"status"`
	Severity    string     `db:"severity"`
	Labels      string     `db:"labels"`
	Annotations string     `db:"annotations"`
	StartsAt    time.Time  `db:"starts_at"`
	EndsAt      *time.Time `db:"ends_at"`
	ReceivedAt  time.Time  `db:"received_at"`
	GroupKey    string     `db:"group_key"`
	PayloadJSON string     `db:"payload_json"`
}

type AnalysisRecord struct {
	ID           string    `db:"id"`
	AlertID      string    `db:"alert_id"`
	Mode         string    `db:"mode"`
	ResultJSON   string    `db:"result_json"`
	ModelUsed    string    `db:"model_used"`
	InputTokens  int       `db:"input_tokens"`
	OutputTokens int       `db:"output_tokens"`
	LatencyMs    int64     `db:"latency_ms"`
	CreatedAt    time.Time `db:"created_at"`
}

type ApprovalRecord struct {
	ID               string     `db:"id"`
	AlertID          string     `db:"alert_id"`
	PlanJSON         string     `db:"plan_json"`
	Status           string     `db:"status"`
	RequestedAt      time.Time  `db:"requested_at"`
	RespondedAt      *time.Time `db:"responded_at"`
	ApproverID       string     `db:"approver_id"`
	ApproverName     string     `db:"approver_name"`
	Comment          string     `db:"comment"`
	LarkMessageID    string     `db:"lark_message_id"`
	ExpiresAt        time.Time  `db:"expires_at"`
	ParentApprovalID string     `db:"parent_approval_id"`
}

type ExecutionLog struct {
	ID          string     `db:"id"`
	ApprovalID  string     `db:"approval_id"`
	AlertID     string     `db:"alert_id"`
	Step        int        `db:"step"`
	CommandType string     `db:"command_type"`
	Target      string     `db:"target"`
	Command     string     `db:"command"`
	Status      string     `db:"status"`
	Output      string     `db:"output"`
	Error       string     `db:"error"`
	StartedAt   time.Time  `db:"started_at"`
	FinishedAt  *time.Time `db:"finished_at"`
	ExecutedBy  string     `db:"executed_by"`
}

type AlertFilter struct {
	Status    *string
	Severity  *string
	AlertName *string
	Since     *time.Time
	Until     *time.Time
	Limit     int
	Offset    int
}

type ApprovalFilter struct {
	Status *string
	Limit  int
	Offset int
}

// Conversation represents a chat thread bound to an alert.
type Conversation struct {
	ID            string    `db:"id"`
	AlertID       string    `db:"alert_id"`
	ApprovalID    string    `db:"approval_id"`
	LarkChatID    string    `db:"lark_chat_id"`
	RootMessageID string    `db:"root_message_id"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

// Message is a single turn in a conversation.
type Message struct {
	ID              string    `db:"id"`
	ConversationID  string    `db:"conversation_id"`
	Role            string    `db:"role"` // "user", "assistant", "system"
	Content         string    `db:"content"`
	LarkMessageID   string    `db:"lark_message_id"`
	ParentLarkMsgID string    `db:"parent_lark_msg_id"`
	UserOpenID      string    `db:"user_open_id"`
	UserName        string    `db:"user_name"`
	CreatedAt       time.Time `db:"created_at"`
}

// Store is the persistence interface. Implementations must be safe for concurrent use.
type Store interface {
	// Alert records
	SaveAlert(ctx context.Context, alert *AlertRecord) error
	GetAlert(ctx context.Context, id string) (*AlertRecord, error)
	ListAlerts(ctx context.Context, filter AlertFilter) ([]*AlertRecord, error)

	// Analysis records
	SaveAnalysis(ctx context.Context, analysis *AnalysisRecord) error
	GetAnalysis(ctx context.Context, alertID string) (*AnalysisRecord, error)

	// Approval records
	SaveApproval(ctx context.Context, approval *ApprovalRecord) error
	GetApproval(ctx context.Context, id string) (*ApprovalRecord, error)
	UpdateApprovalStatus(ctx context.Context, id string, status string, approverID string, comment string) error
	ListApprovals(ctx context.Context, filter ApprovalFilter) ([]*ApprovalRecord, error)

	// Execution logs
	SaveExecutionLog(ctx context.Context, log *ExecutionLog) error
	ListExecutionLogs(ctx context.Context, approvalID string) ([]*ExecutionLog, error)

	// Conversations
	SaveConversation(ctx context.Context, conv *Conversation) error
	GetConversation(ctx context.Context, id string) (*Conversation, error)
	GetConversationByRootMessage(ctx context.Context, rootMessageID string) (*Conversation, error)
	GetConversationByAlert(ctx context.Context, alertID string) (*Conversation, error)
	UpdateConversationApproval(ctx context.Context, id, approvalID string) error

	// Messages
	SaveMessage(ctx context.Context, msg *Message) error
	GetMessageByLarkID(ctx context.Context, larkMessageID string) (*Message, error)
	ListMessages(ctx context.Context, conversationID string, limit int) ([]*Message, error)

	// Event idempotency. MarkEventProcessed inserts the event_id; returns true if
	// this was the first time (caller should proceed), false if already processed
	// (caller should skip).
	MarkEventProcessed(ctx context.Context, eventID string) (firstTime bool, err error)
	PurgeOldEvents(ctx context.Context, olderThan time.Time) (int, error)

	// Lifecycle
	Migrate(ctx context.Context) error
	Close() error
}
