package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type postgresStore struct {
	db *sql.DB
}

func NewPostgres(dsn string, maxOpen, maxIdle int, maxLifetime time.Duration) (Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(maxLifetime)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	return &postgresStore{db: db}, nil
}

func (s *postgresStore) Migrate(ctx context.Context) error {
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

func (s *postgresStore) Close() error {
	return s.db.Close()
}

// Alert records

func (s *postgresStore) SaveAlert(ctx context.Context, a *AlertRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alerts (id, fingerprint, alert_name, status, severity, labels, annotations, starts_at, ends_at, received_at, group_key, payload_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		a.ID, a.Fingerprint, a.AlertName, a.Status, a.Severity, a.Labels, a.Annotations,
		a.StartsAt, a.EndsAt, a.ReceivedAt, a.GroupKey, a.PayloadJSON,
	)
	return err
}

func (s *postgresStore) GetAlert(ctx context.Context, id string) (*AlertRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, fingerprint, alert_name, status, severity, labels, annotations, starts_at, ends_at, received_at, group_key, payload_json
		 FROM alerts WHERE id = $1`, id)
	a := &AlertRecord{}
	err := row.Scan(&a.ID, &a.Fingerprint, &a.AlertName, &a.Status, &a.Severity,
		&a.Labels, &a.Annotations, &a.StartsAt, &a.EndsAt, &a.ReceivedAt, &a.GroupKey, &a.PayloadJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (s *postgresStore) ListAlerts(ctx context.Context, filter AlertFilter) ([]*AlertRecord, error) {
	query := "SELECT id, fingerprint, alert_name, status, severity, labels, annotations, starts_at, ends_at, received_at, group_key, payload_json FROM alerts WHERE 1=1"
	var args []any
	argIdx := 1

	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}
	if filter.Severity != nil {
		query += fmt.Sprintf(" AND severity = $%d", argIdx)
		args = append(args, *filter.Severity)
		argIdx++
	}
	if filter.AlertName != nil {
		query += fmt.Sprintf(" AND alert_name = $%d", argIdx)
		args = append(args, *filter.AlertName)
		argIdx++
	}
	if filter.Since != nil {
		query += fmt.Sprintf(" AND received_at >= $%d", argIdx)
		args = append(args, *filter.Since)
		argIdx++
	}
	if filter.Until != nil {
		query += fmt.Sprintf(" AND received_at <= $%d", argIdx)
		args = append(args, *filter.Until)
		argIdx++
	}

	query += " ORDER BY received_at DESC"

	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
		argIdx++
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

func (s *postgresStore) SaveAnalysis(ctx context.Context, a *AnalysisRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO analyses (id, alert_id, mode, result_json, model_used, input_tokens, output_tokens, latency_ms, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		a.ID, a.AlertID, a.Mode, a.ResultJSON, a.ModelUsed, a.InputTokens, a.OutputTokens, a.LatencyMs, a.CreatedAt,
	)
	return err
}

func (s *postgresStore) GetAnalysis(ctx context.Context, alertID string) (*AnalysisRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, mode, result_json, model_used, input_tokens, output_tokens, latency_ms, created_at
		 FROM analyses WHERE alert_id = $1 ORDER BY created_at DESC LIMIT 1`, alertID)
	a := &AnalysisRecord{}
	err := row.Scan(&a.ID, &a.AlertID, &a.Mode, &a.ResultJSON, &a.ModelUsed, &a.InputTokens, &a.OutputTokens, &a.LatencyMs, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

// Approval records

func (s *postgresStore) SaveApproval(ctx context.Context, a *ApprovalRecord) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO approvals (id, alert_id, plan_json, status, requested_at, lark_message_id, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.ID, a.AlertID, a.PlanJSON, a.Status, a.RequestedAt, a.LarkMessageID, a.ExpiresAt,
	)
	return err
}

func (s *postgresStore) GetApproval(ctx context.Context, id string) (*ApprovalRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, alert_id, plan_json, status, requested_at, responded_at, approver_id, approver_name, comment, lark_message_id, expires_at
		 FROM approvals WHERE id = $1`, id)
	a := &ApprovalRecord{}
	err := row.Scan(&a.ID, &a.AlertID, &a.PlanJSON, &a.Status, &a.RequestedAt, &a.RespondedAt,
		&a.ApproverID, &a.ApproverName, &a.Comment, &a.LarkMessageID, &a.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return a, err
}

func (s *postgresStore) UpdateApprovalStatus(ctx context.Context, id string, status string, approverID string, comment string) error {
	now := time.Now()
	_, err := s.db.ExecContext(ctx,
		`UPDATE approvals SET status = $1, responded_at = $2, approver_id = $3, comment = $4 WHERE id = $5`,
		status, &now, approverID, comment, id,
	)
	return err
}

func (s *postgresStore) ListApprovals(ctx context.Context, filter ApprovalFilter) ([]*ApprovalRecord, error) {
	query := `SELECT id, alert_id, plan_json, status, requested_at, responded_at, approver_id, approver_name, comment, lark_message_id, expires_at FROM approvals WHERE 1=1`
	var args []any
	argIdx := 1

	if filter.Status != nil {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *filter.Status)
		argIdx++
	}
	query += " ORDER BY requested_at DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
		argIdx++
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

func (s *postgresStore) SaveExecutionLog(ctx context.Context, l *ExecutionLog) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO execution_logs (id, approval_id, alert_id, step, command_type, target, command, status, output, error, started_at, finished_at, executed_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		l.ID, l.ApprovalID, l.AlertID, l.Step, l.CommandType, l.Target, l.Command,
		l.Status, l.Output, l.Error, l.StartedAt, l.FinishedAt, l.ExecutedBy,
	)
	return err
}

func (s *postgresStore) ListExecutionLogs(ctx context.Context, approvalID string) ([]*ExecutionLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, approval_id, alert_id, step, command_type, target, command, status, output, error, started_at, finished_at, executed_by
		 FROM execution_logs WHERE approval_id = $1 ORDER BY step ASC`, approvalID)
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
