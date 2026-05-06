// Package incidents implements historical incident retrieval. Given a new
// alert, it finds the most relevant past incidents from the persistent store
// and ranks them with the LLM so the main analyzer can use them as evidence.
//
// Retrieval is two-stage: SQL pre-filter (fast, broad) → LLM semantic rank
// (small, precise). This avoids needing an embedding service while keeping
// per-alert cost bounded — the ranker prompt only sees compact summaries.
package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/alert-genie/alert-genie/internal/store"
)

// HistoricalIncident is the lean structure passed to the main analyzer's
// prompt. It carries enough context for the LLM to learn from past incidents
// without sending entire AnalysisResult JSON blobs.
type HistoricalIncident struct {
	AlertID         string    `json:"alert_id"`
	AlertName       string    `json:"alert_name"`
	Severity        string    `json:"severity"`
	StartedAt       time.Time `json:"started_at"`
	Labels          string    `json:"labels"` // JSON
	AnalysisSummary string    `json:"analysis_summary"`
	RootCause       string    `json:"root_cause"`
	HealingSummary  string    `json:"healing_summary"`
	FinalStatus     string    `json:"final_status"`
	FeedbackSummary string    `json:"feedback_summary"`
	ResolvedVia     string    `json:"resolved_via"`
	RelevanceReason string    `json:"relevance_reason"` // why the LLM picked this one
}

// CurrentAlert is the slim view of the new alert that needs context.
type CurrentAlert struct {
	AlertID     string
	AlertName   string
	Severity    string
	Labels      map[string]string
	Annotations map[string]string
	Summary     string // optional pre-computed summary, fed straight to the ranker
}

// Retriever finds and ranks historical incidents for a new alert.
type Retriever interface {
	Retrieve(ctx context.Context, current CurrentAlert) ([]HistoricalIncident, error)
}

// Ranker is the LLM-based scoring step. The pipeline wires this to the
// analyzer's RankIncidents method.
type Ranker interface {
	RankIncidents(ctx context.Context, current CurrentAlert, candidates []*store.HistoricalCandidate, topK int) ([]RankedIncident, error)
}

// RankedIncident is the output of the LLM ranker.
type RankedIncident struct {
	AlertID         string  `json:"alert_id"`
	RelevanceScore  float64 `json:"relevance_score"`  // 0.0-1.0
	RelevanceReason string  `json:"relevance_reason"` // 1-2 sentence
}

// Config tunes retriever behavior.
type Config struct {
	// CandidatePoolSize is the SQL pre-filter cap. 50 is a good balance.
	CandidatePoolSize int
	// TopK is the final number of incidents fed to the main analyzer.
	TopK int
	// LookbackDays bounds candidate freshness (older incidents are skipped).
	LookbackDays int
	// MinCandidatesForLLM is the threshold below which we skip the LLM ranker
	// and just pass back all candidates ordered by recency. Saves a Claude call
	// when there's nothing to rank against.
	MinCandidatesForLLM int
	// Enabled is the master switch. When false, Retrieve returns nil quickly.
	Enabled bool
}

// DefaultConfig returns recommended defaults.
func DefaultConfig() Config {
	return Config{
		CandidatePoolSize:   50,
		TopK:                3,
		LookbackDays:        90,
		MinCandidatesForLLM: 2,
		Enabled:             true,
	}
}

// retriever is the default Retriever implementation.
type retriever struct {
	store  store.Store
	ranker Ranker
	cfg    Config
	logger *slog.Logger
}

// New constructs a Retriever.
func New(st store.Store, ranker Ranker, cfg Config, logger *slog.Logger) Retriever {
	return &retriever{store: st, ranker: ranker, cfg: cfg, logger: logger}
}

// Retrieve runs the two-stage retrieval and returns up to TopK incidents.
// On any non-fatal error the function returns the best-effort partial result
// rather than failing the calling pipeline — historical context is an
// enrichment, not a requirement.
func (r *retriever) Retrieve(ctx context.Context, current CurrentAlert) ([]HistoricalIncident, error) {
	if !r.cfg.Enabled {
		return nil, nil
	}
	if r.store == nil {
		return nil, nil
	}

	// Stage 1: SQL pre-filter
	since := time.Now().AddDate(0, 0, -r.cfg.LookbackDays)
	q := store.HistoricalQuery{
		AlertName:      current.AlertName,
		Labels:         current.Labels,
		ExcludeAlertID: current.AlertID,
		Limit:          r.cfg.CandidatePoolSize,
		Since:          &since,
	}
	candidates, err := r.store.FindHistoricalCandidates(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("find candidates: %w", err)
	}
	if len(candidates) == 0 {
		r.logger.Debug("no historical candidates for alert", "alert_name", current.AlertName)
		return nil, nil
	}

	// Stage 2: LLM rank — but only if there are enough candidates to bother.
	if len(candidates) <= r.cfg.MinCandidatesForLLM || r.ranker == nil {
		// Skip ranker; return up to TopK by recency.
		out := convertCandidates(candidates, r.cfg.TopK, "recency-only fallback")
		return out, nil
	}

	ranked, err := r.ranker.RankIncidents(ctx, current, candidates, r.cfg.TopK)
	if err != nil {
		// Soft fall-back: ranker failed, return recency order so the caller
		// still gets SOMETHING relevant.
		r.logger.Warn("LLM ranker failed, falling back to recency order",
			"err", err, "candidates", len(candidates))
		return convertCandidates(candidates, r.cfg.TopK, "ranker error fallback"), nil
	}

	// Materialize ranked → HistoricalIncident, preserving ranker order.
	candByID := make(map[string]*store.HistoricalCandidate, len(candidates))
	for _, c := range candidates {
		candByID[c.AlertID] = c
	}
	out := make([]HistoricalIncident, 0, len(ranked))
	for _, rk := range ranked {
		c, ok := candByID[rk.AlertID]
		if !ok {
			// LLM hallucinated an alert_id not in candidates; skip.
			continue
		}
		out = append(out, toIncident(c, rk.RelevanceReason))
	}
	if len(out) == 0 {
		// LLM returned all hallucinated IDs — fall back to recency.
		return convertCandidates(candidates, r.cfg.TopK, "all ranks hallucinated"), nil
	}
	return out, nil
}

func convertCandidates(cs []*store.HistoricalCandidate, topK int, reason string) []HistoricalIncident {
	if topK <= 0 || topK > len(cs) {
		topK = len(cs)
	}
	out := make([]HistoricalIncident, 0, topK)
	for i := 0; i < topK; i++ {
		out = append(out, toIncident(cs[i], reason))
	}
	return out
}

func toIncident(c *store.HistoricalCandidate, reason string) HistoricalIncident {
	return HistoricalIncident{
		AlertID:         c.AlertID,
		AlertName:       c.AlertName,
		Severity:        c.Severity,
		StartedAt:       c.StartsAt,
		Labels:          c.Labels,
		AnalysisSummary: c.AnalysisSummary,
		RootCause:       c.RootCause,
		HealingSummary:  c.HealingSummary,
		FinalStatus:     c.FinalStatus,
		FeedbackSummary: c.FeedbackSummary,
		ResolvedVia:     c.ResolvedVia,
		RelevanceReason: reason,
	}
}

// Convert exposes the conversion helper for callers (e.g. analyzer adapter)
// that need to turn store candidates into the analyzer-facing structure.
func Convert(c *store.HistoricalCandidate, reason string) HistoricalIncident {
	return toIncident(c, reason)
}

// SerializeForRanker compacts a candidate into a JSON-safe map for the
// ranker prompt. We deliberately drop fields that wouldn't help relevance
// scoring (e.g. internal IDs other than alert_id).
func SerializeForRanker(cs []*store.HistoricalCandidate) (string, error) {
	type item struct {
		AlertID         string `json:"alert_id"`
		AlertName       string `json:"alert_name"`
		Severity        string `json:"severity"`
		StartedAt       string `json:"started_at"`
		Labels          any    `json:"labels"`
		AnalysisSummary string `json:"analysis_summary"`
		RootCause       string `json:"root_cause"`
		HealingSummary  string `json:"healing_summary"`
		FinalStatus     string `json:"final_status"`
		FeedbackSummary string `json:"feedback_summary"`
		ResolvedVia     string `json:"resolved_via"`
	}
	out := make([]item, 0, len(cs))
	for _, c := range cs {
		var labels any
		if c.Labels != "" {
			_ = json.Unmarshal([]byte(c.Labels), &labels) // best-effort
		}
		out = append(out, item{
			AlertID:         c.AlertID,
			AlertName:       c.AlertName,
			Severity:        c.Severity,
			StartedAt:       c.StartsAt.Format(time.RFC3339),
			Labels:          labels,
			AnalysisSummary: c.AnalysisSummary,
			RootCause:       c.RootCause,
			HealingSummary:  c.HealingSummary,
			FinalStatus:     c.FinalStatus,
			FeedbackSummary: c.FeedbackSummary,
			ResolvedVia:     c.ResolvedVia,
		})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
