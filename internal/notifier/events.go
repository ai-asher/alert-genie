package notifier

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ChatEvent represents an inbound chat message from Lark.
//
// It is the normalized form of Lark's `im.message.receive_v1` event, with the
// message text already stripped of any bot @-mention prefixes.
type ChatEvent struct {
	EventID         string
	ChatID          string
	MessageID       string // ID of THIS message
	RootMessageID   string // ID of the thread root (original card)
	ParentMessageID string // ID of the immediate parent (the message being replied to)
	SenderOpenID    string
	SenderName      string // may be empty
	Text            string // message text with bot mentions stripped
	CreatedAt       time.Time
	MentionedBot    bool
}

// EventDeduper is implemented by anything that can claim an event ID for
// idempotent processing. MarkProcessed returns true if this is the first time
// the event_id has been seen, false if it was already processed.
type EventDeduper interface {
	MarkEventProcessed(ctx context.Context, eventID string) (bool, error)
}

// EventHandler handles inbound Lark events delivered to the event subscription
// endpoint. It is intentionally separate from CallbackHandler — the two
// endpoints use different request formats and serve different purposes.
//
// EventHandler currently supports the URL verification challenge and the
// `im.message.receive_v1` event type for text messages. Other event types and
// non-text messages are acknowledged but ignored.
type EventHandler struct {
	verificationToken string
	botOpenID         string // optional, used to detect self-messages and bot mentions
	botName           string // optional, used as fallback to detect bot mentions
	deduper           EventDeduper
	ProcessFunc       func(ctx context.Context, ev ChatEvent) error
}

// NewEventHandler creates a new EventHandler.
//
// botOpenID and botName are optional. If both are empty, MentionedBot on the
// emitted ChatEvent will be inferred from whether the message has any mentions
// at all.
//
// deduper is required: Lark retries event delivery on network errors and on
// timeouts; without idempotency the same event_id will trigger ProcessFunc
// multiple times. Pass a store-backed implementation in production. Tests may
// pass a no-op (always returning true) impl.
func NewEventHandler(verificationToken, botOpenID, botName string, deduper EventDeduper, processFunc func(ctx context.Context, ev ChatEvent) error) *EventHandler {
	return &EventHandler{
		verificationToken: verificationToken,
		botOpenID:         botOpenID,
		botName:           botName,
		deduper:           deduper,
		ProcessFunc:       processFunc,
	}
}

// eventRequest models the envelope Lark posts to the event subscription
// endpoint. It also covers the URL verification challenge variant which
// shares the same endpoint but a different shape.
type eventRequest struct {
	// URL verification fields (only set when Type == "url_verification").
	Challenge string `json:"challenge"`
	Token     string `json:"token"`
	Type      string `json:"type"`

	// Schema 2.0 envelope (set for real events).
	Schema string          `json:"schema"`
	Header eventHeader     `json:"header"`
	Event  json.RawMessage `json:"event"`
}

type eventHeader struct {
	EventID    string `json:"event_id"`
	Token      string `json:"token"`
	CreateTime string `json:"create_time"`
	AppID      string `json:"app_id"`
	TenantKey  string `json:"tenant_key"`
	EventType  string `json:"event_type"`
}

// messageReceiveEvent is the body of an `im.message.receive_v1` event.
type messageReceiveEvent struct {
	Sender struct {
		SenderID struct {
			OpenID string `json:"open_id"`
			UserID string `json:"user_id"`
		} `json:"sender_id"`
		SenderType string `json:"sender_type"`
		TenantKey  string `json:"tenant_key"`
	} `json:"sender"`
	Message struct {
		MessageID   string `json:"message_id"`
		RootID      string `json:"root_id"`
		ParentID    string `json:"parent_id"`
		CreateTime  string `json:"create_time"`
		ChatID      string `json:"chat_id"`
		ChatType    string `json:"chat_type"`
		MessageType string `json:"message_type"`
		Content     string `json:"content"` // JSON-encoded string
		Mentions    []struct {
			Key  string `json:"key"`
			Name string `json:"name"`
			ID   struct {
				OpenID string `json:"open_id"`
				UserID string `json:"user_id"`
			} `json:"id"`
			TenantKey string `json:"tenant_key"`
		} `json:"mentions"`
	} `json:"message"`
}

// HandleEvent processes an HTTP request from Lark's event subscription
// endpoint. It handles the URL verification handshake, validates the
// verification token, and dispatches `im.message.receive_v1` events to
// ProcessFunc.
//
// Lark requires a fast acknowledgement (HTTP 200) — this handler responds
// before doing any heavy work other than parsing.
func (h *EventHandler) HandleEvent(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req eventRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	// Handle Lark URL verification challenge (same shape as the card callback).
	if req.Type == "url_verification" {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]string{
			"challenge": req.Challenge,
		})
		w.Write(resp)
		return
	}

	// Verify token from the schema 2.0 header.
	if req.Header.Token != h.verificationToken {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	// Only handle inbound message events; ack everything else.
	if req.Header.EventType != "im.message.receive_v1" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var msg messageReceiveEvent
	if err := json.Unmarshal(req.Event, &msg); err != nil {
		slog.Warn("failed to decode message event", "err", err, "event_id", req.Header.EventID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Skip messages where the bot itself is the sender. Best-effort: only
	// possible when botOpenID is configured.
	if h.botOpenID != "" && msg.Sender.SenderID.OpenID == h.botOpenID {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Only handle text messages for now.
	if msg.Message.MessageType != "text" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse the JSON-encoded content string into its text payload.
	var contentPayload struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(msg.Message.Content), &contentPayload); err != nil {
		slog.Warn("failed to decode message content",
			"err", err,
			"event_id", req.Header.EventID,
			"message_id", msg.Message.MessageID)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Strip the @_user_N mention placeholders so ProcessFunc receives the
	// human-readable text without bot mention markers.
	text := contentPayload.Text
	for _, m := range msg.Message.Mentions {
		if m.Key != "" {
			text = strings.ReplaceAll(text, m.Key, "")
		}
	}
	text = strings.TrimSpace(text)

	// Detect whether the bot was mentioned. Prefer matching by botOpenID; fall
	// back to botName; if both are empty, infer from the presence of any
	// mention (events fire on @-mentions in most group configurations).
	mentioned := false
	if h.botOpenID != "" || h.botName != "" {
		for _, m := range msg.Message.Mentions {
			if h.botOpenID != "" && m.ID.OpenID == h.botOpenID {
				mentioned = true
				break
			}
			if h.botName != "" && m.Name == h.botName {
				mentioned = true
				break
			}
		}
	} else {
		mentioned = len(msg.Message.Mentions) > 0
	}

	if !mentioned {
		w.WriteHeader(http.StatusOK)
		return
	}

	ev := ChatEvent{
		EventID:         req.Header.EventID,
		ChatID:          msg.Message.ChatID,
		MessageID:       msg.Message.MessageID,
		RootMessageID:   msg.Message.RootID,
		ParentMessageID: msg.Message.ParentID,
		SenderOpenID:    msg.Sender.SenderID.OpenID,
		Text:            text,
		CreatedAt:       parseLarkMillis(msg.Message.CreateTime),
		MentionedBot:    mentioned,
	}

	// Idempotency: claim the event_id. Lark retries on network errors and timeouts;
	// without this, the same event triggers ProcessFunc multiple times.
	if h.deduper != nil && ev.EventID != "" {
		firstTime, err := h.deduper.MarkEventProcessed(r.Context(), ev.EventID)
		if err != nil {
			slog.Error("dedupe event failed, processing anyway",
				"err", err, "event_id", ev.EventID)
		} else if !firstTime {
			slog.Debug("duplicate event ignored", "event_id", ev.EventID)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Ack Lark immediately so we stay within their 3-second deadline. ProcessFunc
	// runs asynchronously in a detached context so it survives this handler's
	// request scope (Go cancels r.Context() when the handler returns).
	w.WriteHeader(http.StatusOK)

	if h.ProcessFunc == nil {
		return
	}

	go func(ev ChatEvent) {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := h.ProcessFunc(ctx, ev); err != nil {
			slog.Error("process chat event failed",
				"err", err,
				"event_id", ev.EventID,
				"message_id", ev.MessageID)
		}
	}(ev)
}

// parseLarkMillis parses a Lark timestamp string (milliseconds since epoch) to
// a time.Time. Returns the zero time on failure.
func parseLarkMillis(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	ms, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}
