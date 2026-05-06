-- Add parent_approval_id to approvals for revision chain
-- (SQLite tolerates "ADD COLUMN" without IF NOT EXISTS; we ignore duplicate-column errors at the Go layer)
ALTER TABLE approvals ADD COLUMN parent_approval_id TEXT;

CREATE INDEX IF NOT EXISTS idx_approvals_parent ON approvals(parent_approval_id);

-- Conversations: a conversation is bound to an alert (and optionally an approval)
CREATE TABLE IF NOT EXISTS conversations (
    id              TEXT PRIMARY KEY,
    alert_id        TEXT NOT NULL REFERENCES alerts(id),
    approval_id     TEXT,
    lark_chat_id    TEXT NOT NULL,
    root_message_id TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_conversations_alert_id ON conversations(alert_id);
CREATE INDEX IF NOT EXISTS idx_conversations_root_message ON conversations(root_message_id);

-- Messages: every turn of conversation (user message, bot reply, etc.)
CREATE TABLE IF NOT EXISTS messages (
    id                TEXT PRIMARY KEY,
    conversation_id   TEXT NOT NULL REFERENCES conversations(id),
    role              TEXT NOT NULL,    -- "user", "assistant", "system"
    content           TEXT NOT NULL,
    lark_message_id   TEXT,             -- the lark message ID this maps to
    parent_lark_msg_id TEXT,            -- the message this was replying to
    user_open_id      TEXT,             -- for user messages
    user_name         TEXT,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_lark_message_id ON messages(lark_message_id);
CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at);
