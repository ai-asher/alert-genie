CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    alert_name      TEXT NOT NULL,
    status          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    labels          TEXT NOT NULL,
    annotations     TEXT NOT NULL,
    starts_at       TIMESTAMP NOT NULL,
    ends_at         TIMESTAMP,
    received_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    group_key       TEXT NOT NULL,
    payload_json    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);
CREATE INDEX IF NOT EXISTS idx_alerts_alert_name ON alerts(alert_name);
CREATE INDEX IF NOT EXISTS idx_alerts_received_at ON alerts(received_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    alert_id        TEXT NOT NULL REFERENCES alerts(id),
    mode            TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    model_used      TEXT NOT NULL,
    input_tokens    INTEGER NOT NULL,
    output_tokens   INTEGER NOT NULL,
    latency_ms      INTEGER NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_analyses_alert_id ON analyses(alert_id);

CREATE TABLE IF NOT EXISTS approvals (
    id              TEXT PRIMARY KEY,
    alert_id        TEXT NOT NULL REFERENCES alerts(id),
    plan_json       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    requested_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    responded_at    TIMESTAMP,
    approver_id     TEXT,
    approver_name   TEXT,
    comment         TEXT,
    lark_message_id TEXT NOT NULL,
    expires_at      TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_alert_id ON approvals(alert_id);

CREATE TABLE IF NOT EXISTS execution_logs (
    id              TEXT PRIMARY KEY,
    approval_id     TEXT NOT NULL REFERENCES approvals(id),
    alert_id        TEXT NOT NULL REFERENCES alerts(id),
    step            INTEGER NOT NULL,
    command_type    TEXT NOT NULL,
    target          TEXT NOT NULL,
    command         TEXT NOT NULL,
    status          TEXT NOT NULL,
    output          TEXT,
    error           TEXT,
    started_at      TIMESTAMP NOT NULL,
    finished_at     TIMESTAMP,
    executed_by     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_execution_logs_approval_id ON execution_logs(approval_id);
CREATE INDEX IF NOT EXISTS idx_execution_logs_alert_id ON execution_logs(alert_id);
