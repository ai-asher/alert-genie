// Package incidents — adapters connecting the retriever to other internal
// packages without introducing import cycles.

package incidents

import (
	"context"
	"encoding/json"

	"github.com/alert-genie/alert-genie/internal/analyzer"
	"github.com/alert-genie/alert-genie/internal/store"
)

// AnalyzerRanker adapts analyzer.Analyzer to the Ranker interface so the
// retriever can call into the existing Claude client without duplicating
// HTTP/auth/retry plumbing.
type AnalyzerRanker struct {
	A analyzer.Analyzer
}

// RankIncidents implements incidents.Ranker.
func (r *AnalyzerRanker) RankIncidents(ctx context.Context, current CurrentAlert, candidates []*store.HistoricalCandidate, topK int) ([]RankedIncident, error) {
	currentJSON, err := serializeCurrent(current)
	if err != nil {
		return nil, err
	}
	candJSON, err := SerializeForRanker(candidates)
	if err != nil {
		return nil, err
	}

	resp, err := r.A.RankIncidents(ctx, analyzer.RankRequest{
		CurrentAlertJSON: currentJSON,
		CandidatesJSON:   candJSON,
		TopK:             topK,
	})
	if err != nil {
		return nil, err
	}

	out := make([]RankedIncident, 0, len(resp.Ranked))
	for _, r := range resp.Ranked {
		out = append(out, RankedIncident{
			AlertID:         r.AlertID,
			RelevanceScore:  r.RelevanceScore,
			RelevanceReason: r.RelevanceReason,
		})
	}
	return out, nil
}

func serializeCurrent(c CurrentAlert) (string, error) {
	b, err := json.Marshal(struct {
		AlertID     string            `json:"alert_id"`
		AlertName   string            `json:"alert_name"`
		Severity    string            `json:"severity"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
		Summary     string            `json:"summary,omitempty"`
	}{
		AlertID:     c.AlertID,
		AlertName:   c.AlertName,
		Severity:    c.Severity,
		Labels:      c.Labels,
		Annotations: c.Annotations,
		Summary:     c.Summary,
	})
	if err != nil {
		return "", err
	}
	return string(b), nil
}
