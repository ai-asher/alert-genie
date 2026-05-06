CREATE INDEX IF NOT EXISTS idx_approvals_parent ON approvals(parent_approval_id);

CREATE TABLE IF NOT EXISTS conversations (
    id              TEXT PRIMARY KEY,
    alert_id        TEXT NOT NULL,
    approval_id     TEXT,
    lark_chat_id    TEXT NOT NULL,
    root_message_id TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_conversations_alert_id ON conversations(alert_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_root_message ON conversations(root_message_id);

CREATE TABLE IF NOT EXISTS messages (
    id                  TEXT PRIMARY KEY,
    conversation_id     TEXT NOT NULL,
    role                TEXT NOT NULL,
    content             TEXT NOT NULL,
    lark_message_id     TEXT,
    parent_lark_msg_id  TEXT,
    user_open_id        TEXT,
    user_name           TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_lark_message_id ON messages(lark_message_id) WHERE lark_message_id IS NOT NULL AND lark_message_id != '';
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);

-- Idempotency table for Lark event deduplication.
CREATE TABLE IF NOT EXISTS processed_events (
    event_id     TEXT PRIMARY KEY,
    processed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_processed_events_processed_at ON processed_events(processed_at);
