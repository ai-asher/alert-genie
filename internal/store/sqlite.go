package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type sqliteStore struct {
	db *sql.DB
}

func NewSQLite(path string) (Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	db.SetMaxOpenConns(1) // SQLite doesn't support concurrent writes
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) Migrate(ctx context.Context) error {
	migrations := []string{
		"migrations/001_init.sql",
		"migrations/002_chat_alter.sql", // ALTER TABLE — may fail on re-run, tolerated
		"migrations/003_chat_tables.sql",
	}
	for _, m := range migrations {
		data, err := migrationsFS.ReadFile(m)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m, err)
		}
		if _, err := s.db.ExecContext(ctx, string(data)); err != nil {
			if !isAlreadyExistsErr(err) {
				return fmt.Errorf("run migration %s: %w", m, err)
			}
		}
	}
	return nil
}

func isAlreadyExistsErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "duplicate column") || contains(msg, "already exists")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

// Alert records

func (s *sqliteStore) SaveAlert(ctx context.Context, a *AlertRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alerts (id, fingerprint, alert_name, status, severity, labels, annotations, starts_at, ends_at, received_at, group_key, payload_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Fingerprint, a.AlertName, a.Status, a.Severity, a.Labels, a.Annotations,
		a.StartsAt, a.EndsAt, a.ReceivedAt, a.GroupKey, a.PayloadJSON,
	)
	return err
}

func (s *sqliteStore) GetAlert(ctx context.Context, id string) (*AlertRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, fingerprint, alert_name, status, severity, labels, annotations, starts_at, ends_at, received_at, group_key, payload_json
		 FROM alerts WHERE id = ?`, id)
	a := &AlertRecord{}
	err := row.Scan(&a.ID, &a.Fingerprint, &a.AlertName, &a.Status, &a.Severity,
		&a.Labels, &a.Annotations, &a.StartsAt, &a.EndsAt, &a.ReceivedAt, &a.GroupKey, &a.PayloadJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (s *sqliteStore) ListAlerts(ctx context.Context, filter AlertFilter) ([]*AlertRecord, error) {
	query := "SELECT id, fingerprint, alert_name, status, severity, labels, annotations, starts_at, ends_at, received_at, group_key, payload_json FROM alerts WHERE 1=1"
	var args []any

	if filter.Status != nil {
		query += " AND status = ?"
		args = append(args, *filter.Status)
	}
	if filter.Severity != nil {
		query += " AND severity = ?"
		args = append(args, *filter.Severity)
	}
	if filter.AlertName != nil {
		query += " AND alert_name = ?"
		args = append(args, *filter.AlertName)
	}
	if filter.Since != nil {
		query += " AND received_at >= ?"
		args = append(args, *filter.Since)
	}
	if filter.Until != nil {
		query += " AND received_at <= ?"
		args = append(args, *filter.Until)
	}

	query += " ORDER BY received_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*AlertRecord
	for rows.Next() {
		a := &AlertRecord{}
		if err := rows.Scan(&a.ID, &a.Fingerprint, &a.AlertName, &a.Status, &a.Severity,
			&a.Labels, &a.Annotations, &a.StartsAt, &a.EndsAt, &a.ReceivedAt, &a.GroupKey, &a.PayloadJSON); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// Analysis records

func (s *sqliteStore) SaveAnalysis(ctx context.Context, a *AnalysisRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO analyses (id, alert_id, mode, result_json, model_used, input_tokens, output_tokens, latency_ms, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AlertID, a.Mode, a.ResultJSON, a.ModelUsed, a.InputTokens, a.OutputTokens, a.LatencyMs, a.CreatedAt,
	)
	return err
}

func (s *sqliteStore) GetAnalysis(ctx context.Context, alertID string) (*AnalysisRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, mode, result_json, model_used, input_tokens, output_tokens, latency_ms, created_at
		 FROM analyses WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1`, alertID)
	a := &AnalysisRecord{}
	err := row.Scan(&a.ID, &a.AlertID, &a.Mode, &a.ResultJSON, &a.ModelUsed, &a.InputTokens, &a.OutputTokens, &a.LatencyMs, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// Approval records

func (s *sqliteStore) SaveApproval(ctx context.Context, a *ApprovalRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approvals (id, alert_id, plan_json, status, requested_at, lark_message_id, expires_at, parent_approval_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AlertID, a.PlanJSON, a.Status, a.RequestedAt, a.LarkMessageID, a.ExpiresAt, a.ParentApprovalID,
	)
	return err
}

func (s *sqliteStore) GetApproval(ctx context.Context, id string) (*ApprovalRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, plan_json, status, requested_at, responded_at, approver_id, approver_name, comment, lark_message_id, expires_at, COALESCE(parent_approval_id, '')
		 FROM approvals WHERE id = ?`, id)
	a := &ApprovalRecord{}
	err := row.Scan(&a.ID, &a.AlertID, &a.PlanJSON, &a.Status, &a.RequestedAt, &a.RespondedAt,
		&a.ApproverID, &a.ApproverName, &a.Comment, &a.LarkMessageID, &a.ExpiresAt, &a.ParentApprovalID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (s *sqliteStore) UpdateApprovalStatus(ctx context.Context, id string, status string, approverID string, comment string) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET status = ?, responded_at = ?, approver_id = ?, comment = ? WHERE id = ?`,
		status, &now, approverID, comment, id,
	)
	return err
}

func (s *sqliteStore) ListApprovals(ctx context.Context, filter ApprovalFilter) ([]*ApprovalRecord, error) {
	query := `SELECT id, alert_id, plan_json, status, requested_at, responded_at, approver_id, approver_name, comment, lark_message_id, expires_at, COALESCE(parent_approval_id, '') FROM approvals WHERE 1=1`
	var args []any

	if filter.Status != nil {
		query += " AND status = ?"
		args = append(args, *filter.Status)
	}
	query += " ORDER BY requested_at DESC"
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var approvals []*ApprovalRecord
	for rows.Next() {
		a := &ApprovalRecord{}
		if err := rows.Scan(&a.ID, &a.AlertID, &a.PlanJSON, &a.Status, &a.RequestedAt, &a.RespondedAt,
			&a.ApproverID, &a.ApproverName, &a.Comment, &a.LarkMessageID, &a.ExpiresAt, &a.ParentApprovalID); err != nil {
			return nil, err
		}
		approvals = append(approvals, a)
	}
	return approvals, rows.Err()
}

// Execution logs

func (s *sqliteStore) SaveExecutionLog(ctx context.Context, l *ExecutionLog) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO execution_logs (id, approval_id, alert_id, step, command_type, target, command, status, output, error, started_at, finished_at, executed_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.ApprovalID, l.AlertID, l.Step, l.CommandType, l.Target, l.Command,
		l.Status, l.Output, l.Error, l.StartedAt, l.FinishedAt, l.ExecutedBy,
	)
	return err
}

func (s *sqliteStore) ListExecutionLogs(ctx context.Context, approvalID string) ([]*ExecutionLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, approval_id, alert_id, step, command_type, target, command, status, output, error, started_at, finished_at, executed_by
		 FROM execution_logs WHERE approval_id = ? ORDER BY step ASC`, approvalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []*ExecutionLog
	for rows.Next() {
		l := &ExecutionLog{}
		if err := rows.Scan(&l.ID, &l.ApprovalID, &l.AlertID, &l.Step, &l.CommandType, &l.Target, &l.Command,
			&l.Status, &l.Output, &l.Error, &l.StartedAt, &l.FinishedAt, &l.ExecutedBy); err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// Conversations

func (s *sqliteStore) SaveConversation(ctx context.Context, c *Conversation) error {
	// Upsert by root_message_id (UNIQUE). If a conversation already exists for
	// this root, update approval_id/updated_at instead of failing — this
	// matters when pipeline re-sends the same card message_id (rare) or when
	// the migration's UNIQUE constraint kicks in on a duplicate insert.
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO conversations (id, alert_id, approval_id, lark_chat_id, root_message_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(root_message_id) DO UPDATE SET
		   approval_id = COALESCE(NULLIF(excluded.approval_id, ''), conversations.approval_id),
		   updated_at = excluded.updated_at`,
		c.ID, c.AlertID, c.ApprovalID, c.LarkChatID, c.RootMessageID, c.CreatedAt, c.UpdatedAt,
	)
	return err
}

func (s *sqliteStore) GetConversation(ctx context.Context, id string) (*Conversation, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, COALESCE(approval_id, ''), lark_chat_id, root_message_id, created_at, updated_at
		 FROM conversations WHERE id = ?`, id)
	c := &Conversation{}
	err := row.Scan(&c.ID, &c.AlertID, &c.ApprovalID, &c.LarkChatID, &c.RootMessageID, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *sqliteStore) GetConversationByRootMessage(ctx context.Context, rootMessageID string) (*Conversation, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, COALESCE(approval_id, ''), lark_chat_id, root_message_id, created_at, updated_at
		 FROM conversations WHERE root_message_id = ?`, rootMessageID)
	c := &Conversation{}
	err := row.Scan(&c.ID, &c.AlertID, &c.ApprovalID, &c.LarkChatID, &c.RootMessageID, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *sqliteStore) GetConversationByAlert(ctx context.Context, alertID string) (*Conversation, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, COALESCE(approval_id, ''), lark_chat_id, root_message_id, created_at, updated_at
		 FROM conversations WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1`, alertID)
	c := &Conversation{}
	err := row.Scan(&c.ID, &c.AlertID, &c.ApprovalID, &c.LarkChatID, &c.RootMessageID, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (s *sqliteStore) UpdateConversationApproval(ctx context.Context, id, approvalID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE conversations SET approval_id = ?, updated_at = ? WHERE id = ?`,
		approvalID, time.Now(), id,
	)
	return err
}

// Messages

func (s *sqliteStore) SaveMessage(ctx context.Context, m *Message) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO messages (id, conversation_id, role, content, lark_message_id, parent_lark_msg_id, user_open_id, user_name, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.ConversationID, m.Role, m.Content, m.LarkMessageID, m.ParentLarkMsgID, m.UserOpenID, m.UserName, m.CreatedAt,
	)
	return err
}

func (s *sqliteStore) GetMessageByLarkID(ctx context.Context, larkMessageID string) (*Message, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, conversation_id, role, content, COALESCE(lark_message_id, ''), COALESCE(parent_lark_msg_id, ''), COALESCE(user_open_id, ''), COALESCE(user_name, ''), created_at
		 FROM messages WHERE lark_message_id = ?`, larkMessageID)
	m := &Message{}
	err := row.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.LarkMessageID, &m.ParentLarkMsgID, &m.UserOpenID, &m.UserName, &m.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return m, err
}

func (s *sqliteStore) ListMessages(ctx context.Context, conversationID string, limit int) ([]*Message, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, conversation_id, role, content, COALESCE(lark_message_id, ''), COALESCE(parent_lark_msg_id, ''), COALESCE(user_open_id, ''), COALESCE(user_name, ''), created_at
		 FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?`, conversationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var msgs []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.LarkMessageID, &m.ParentLarkMsgID, &m.UserOpenID, &m.UserName, &m.CreatedAt); err != nil {
			return nil, err
		}
		msgs = append(msgs, m)
	}
	return msgs, rows.Err()
}

// Event idempotency

func (s *sqliteStore) MarkEventProcessed(ctx context.Context, eventID string) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO processed_events (event_id, processed_at) VALUES (?, ?)`,
		eventID, time.Now())
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (s *sqliteStore) PurgeOldEvents(ctx context.Context, olderThan time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM processed_events WHERE processed_at < ?`, olderThan)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}
