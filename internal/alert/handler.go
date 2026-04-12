package alert

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/alert-genie/alert-genie/internal/store"
)

// ProcessFunc is a callback invoked for each non-duplicate firing alert after
// it has been persisted. The pipeline layer sets this to trigger analysis,
// notification, etc.
type ProcessFunc func(ctx context.Context, payload WebhookPayload)

// Handler receives Alertmanager webhook requests, deduplicates, persists, and
// dispatches them for further processing.
type Handler struct {
	store          store.Store
	dedup          *Deduplicator
	severityFilter map[string]struct{} // allowed severities
	logger         *slog.Logger
	ProcessFunc    ProcessFunc
}

// NewHandler creates a Handler. severityFilter lists the severity values that
// should be accepted (e.g. ["critical","warning"]). An empty list accepts all
// severities.
func NewHandler(st store.Store, dedup *Deduplicator, severityFilter []string, logger *slog.Logger) *Handler {
	sf := make(map[string]struct{}, len(severityFilter))
	for _, s := range severityFilter {
		sf[s] = struct{}{}
	}
	return &Handler{
		store:          st,
		dedup:          dedup,
		severityFilter: sf,
		logger:         logger,
	}
}

// HandleWebhook is the HTTP handler for POST /api/v1/webhook.
func (h *Handler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload WebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.logger.Error("failed to decode webhook payload", slog.String("error", err.Error()))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	h.logger.Info("received webhook",
		slog.String("status", payload.Status),
		slog.String("groupKey", payload.GroupKey),
		slog.Int("alertCount", len(payload.Alerts)),
	)

	for _, a := range payload.Alerts {
		if a.Status != "firing" {
			continue
		}

		// Severity filter: skip if severity not in the allowed set (when set is non-empty).
		if len(h.severityFilter) > 0 {
			if _, ok := h.severityFilter[a.Severity()]; !ok {
				h.logger.Debug("alert filtered by severity",
					slog.String("alertname", a.AlertName()),
					slog.String("severity", a.Severity()),
				)
				continue
			}
		}

		// Deduplication check.
		if h.dedup.IsDuplicate(a.Fingerprint, a.StartsAt) {
			h.logger.Debug("duplicate alert suppressed",
				slog.String("fingerprint", a.Fingerprint),
				slog.String("alertname", a.AlertName()),
			)
			continue
		}
		h.dedup.MarkSeen(a.Fingerprint)

		// Generate a UUID for the alert record ID.
		alertID, err := generateUUID()
		if err != nil {
			h.logger.Error("failed to generate alert ID", slog.String("error", err.Error()))
			continue
		}

		// Marshal labels and annotations to JSON strings for storage.
		labelsJSON, _ := json.Marshal(a.Labels)
		annotationsJSON, _ := json.Marshal(a.Annotations)
		payloadJSON, _ := json.Marshal(payload)

		var endsAt *time.Time
		if !a.EndsAt.IsZero() {
			t := a.EndsAt
			endsAt = &t
		}

		record := &store.AlertRecord{
			ID:          alertID,
			Fingerprint: a.Fingerprint,
			AlertName:   a.AlertName(),
			Status:      a.Status,
			Severity:    a.Severity(),
			Labels:      string(labelsJSON),
			Annotations: string(annotationsJSON),
			StartsAt:    a.StartsAt,
			EndsAt:      endsAt,
			ReceivedAt:  time.Now(),
			GroupKey:    payload.GroupKey,
			PayloadJSON: string(payloadJSON),
		}

		if err := h.store.SaveAlert(r.Context(), record); err != nil {
			h.logger.Error("failed to persist alert",
				slog.String("alertID", alertID),
				slog.String("error", err.Error()),
			)
			continue
		}

		h.logger.Info("alert persisted",
			slog.String("alertID", alertID),
			slog.String("alertname", a.AlertName()),
			slog.String("severity", a.Severity()),
		)

		// Dispatch to pipeline asynchronously.
		if h.ProcessFunc != nil {
			go h.ProcessFunc(r.Context(), payload)
		}
	}

	// Alertmanager expects a fast 200 OK.
	w.WriteHeader(http.StatusOK)
}

// generateUUID produces a version-4 UUID string using crypto/rand.
func generateUUID() (string, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", err
	}
	// Set version (4) and variant (RFC 4122).
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16],
	), nil
}
