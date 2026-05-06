-- Per-incident user feedback. One alert may have several feedback rows
-- (e.g. initial 👍 from oncall, later 👎 from postmortem owner). Used to
-- weight historical incident retrieval and to track plan effectiveness.
CREATE TABLE IF NOT EXISTS incident_feedback (
    id              TEXT PRIMARY KEY,
    alert_id        TEXT NOT NULL,
    approval_id     TEXT,
    rating          TEXT NOT NULL,    -- "thumbs_up", "thumbs_down", "comment_only"
    comment         TEXT,
    user_open_id    TEXT,
    user_name       TEXT,
    lark_message_id TEXT,             -- the feedback card message ID for editing later
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_feedback_alert_id ON incident_feedback(alert_id);
CREATE INDEX IF NOT EXISTS idx_feedback_approval_id ON incident_feedback(approval_id);
CREATE INDEX IF NOT EXISTS idx_feedback_rating ON incident_feedback(rating);

-- Aggregated outcome cache for fast historical retrieval. Filled in by the
-- pipeline after feedback or final approval status changes; nothing forces
-- updates so consumers should treat NULL/empty values as "unknown".
CREATE TABLE IF NOT EXISTS alert_outcomes (
    alert_id              TEXT PRIMARY KEY,
    final_approval_status TEXT,  -- "approved", "rejected", "executed_success", "executed_failed", etc.
    feedback_summary      TEXT,  -- e.g. "thumbs_up: 2, thumbs_down: 0; comments: ..."
    resolved_via          TEXT,  -- short text: "kubectl scale to 5 fixed it" — fed to retriever
    updated_at            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_outcomes_updated_at ON alert_outcomes(updated_at);
