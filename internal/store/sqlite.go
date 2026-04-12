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
	data, err := migrationsFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	_, err = s.db.ExecContext(ctx, string(data))
	if err != nil {
		return fmt.Errorf("run migration: %w", err)
	}
	return nil
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
		`INSERT INTO approvals (id, alert_id, plan_json, status, requested_at, lark_message_id, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.AlertID, a.PlanJSON, a.Status, a.RequestedAt, a.LarkMessageID, a.ExpiresAt,
	)
	return err
}

func (s *sqliteStore) GetApproval(ctx context.Context, id string) (*ApprovalRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, plan_json, status, requested_at, responded_at, approver_id, approver_name, comment, lark_message_id, expires_at
		 FROM approvals WHERE id = ?`, id)
	a := &ApprovalRecord{}
	err := row.Scan(&a.ID, &a.AlertID, &a.PlanJSON, &a.Status, &a.RequestedAt, &a.RespondedAt,
		&a.ApproverID, &a.ApproverName, &a.Comment, &a.LarkMessageID, &a.ExpiresAt)
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
	query := `SELECT id, alert_id, plan_json, status, requested_at, responded_at, approver_id, approver_name, comment, lark_message_id, expires_at FROM approvals WHERE 1=1`
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
			&a.ApproverID, &a.ApproverName, &a.Comment, &a.LarkMessageID, &a.ExpiresAt); err != nil {
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
