package runbooks

import (
	"context"
	"sort"
	"strings"
)

// Query is the slim view of an alert handed to the retriever. It mirrors
// what the pipeline already extracts so we don't take a dependency on the
// alert package from inside this leaf module.
type Query struct {
	// AlertName is the canonical alertname label (e.g. "HighMemoryUsage").
	AlertName string
	// Severity is the alert severity ("critical", "warning", ...).
	Severity string
	// Labels carries all alert labels for keyword/tag matching.
	Labels map[string]string
	// Annotations are the alert annotations (summary, description, …).
	// We scan them for keyword matches because a runbook keyword like
	// "OOM" often appears in the annotation summary, not the alertname.
	Annotations map[string]string
}

// Retriever finds the most relevant runbooks for an incoming alert and
// returns a small set of snippets ready for the analyzer prompt.
type Retriever interface {
	// Retrieve returns up to TopK runbook snippets ordered by score (best
	// first). It returns nil with no error when retrieval is disabled or
	// no runbook matches — callers should treat the empty case the same as
	// "no runbooks", not as an error.
	Retrieve(ctx context.Context, current Query) ([]RunbookSnippet, error)
}

// Config tunes retriever behavior.
type Config struct {
	// Enabled is the master switch. When false, Retrieve returns nil quickly.
	Enabled bool
	// TopK is the maximum number of runbook snippets returned.
	TopK int
	// MaxExcerptChars caps the snippet excerpt size to keep prompt size
	// bounded. The full body always lives on disk.
	MaxExcerptChars int
}

// DefaultConfig returns recommended retriever defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:         true,
		TopK:            2,
		MaxExcerptChars: 2000,
	}
}

// retriever is the in-memory Retriever backed by a Store.
type retriever struct {
	store *Store
	cfg   Config
}

// NewRetriever constructs a Retriever that reads runbooks from the given
// Store. The Store is the only authoritative source — the retriever doesn't
// cache snapshots of its own, so reloads picked up by the store are visible
// on the very next call.
func NewRetriever(store *Store, cfg Config) Retriever {
	if cfg.TopK <= 0 {
		cfg.TopK = 2
	}
	if cfg.MaxExcerptChars <= 0 {
		cfg.MaxExcerptChars = 2000
	}
	return &retriever{store: store, cfg: cfg}
}

// scored is an internal scoring record used to rank candidates before we
// truncate them into snippets.
type scored struct {
	rb     *Runbook
	score  float64
	reason string
}

// Retrieve implements Retriever. The scoring is intentionally simple — exact
// alertname matches dominate, then keyword counts, then tag/label overlap.
// We do not call the LLM here: runbooks are authoritative and small in
// number, so a deterministic scorer is both faster and more debuggable.
func (r *retriever) Retrieve(ctx context.Context, current Query) ([]RunbookSnippet, error) {
	if !r.cfg.Enabled || r.store == nil {
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	all := r.store.Snapshot()
	if len(all) == 0 {
		return nil, nil
	}

	// Build a single haystack of lowercased text used for keyword scans:
	// alertname + label values + annotation values. Keys are intentionally
	// excluded because they're rarely meaningful prose.
	haystack := buildHaystack(current)

	candidates := make([]scored, 0, len(all))
	for _, rb := range all {
		s, reason := score(rb, current, haystack)
		if s > 0 {
			candidates = append(candidates, scored{rb: rb, score: s, reason: reason})
		}
	}

	// Sort by score desc, tie-break by title for stability.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].rb.Title < candidates[j].rb.Title
	})

	topK := r.cfg.TopK
	if topK > len(candidates) {
		topK = len(candidates)
	}
	out := make([]RunbookSnippet, 0, topK)
	for i := 0; i < topK; i++ {
		c := candidates[i]
		out = append(out, RunbookSnippet{
			Title:           c.rb.Title,
			Source:          c.rb.ID,
			RelevanceReason: c.reason,
			Excerpt:         excerpt(c.rb, r.cfg.MaxExcerptChars),
		})
	}
	return out, nil
}

// score computes a relevance score for one runbook against one alert and
// returns (score, humanReason). The reason is a short string that's fed
// straight into the prompt so the LLM (and humans) can see WHY this runbook
// was matched.
//
// Scoring rules:
//   - exact alertname match (case-insensitive): +1.0  (dominant signal)
//   - each keyword that appears in the haystack: +0.2 (capped at +1.0)
//   - each tag that matches a label key/value substring: +0.1 (capped at +0.5)
//
// Keyword/tag scores are deliberately bounded so a runbook with 30 keywords
// can't out-rank a runbook with an exact alertname match.
func score(rb *Runbook, q Query, haystack string) (float64, string) {
	var total float64
	var reasons []string

	// 1. Alertname exact match (case-insensitive)
	for _, an := range rb.AlertNames {
		if strings.EqualFold(an, q.AlertName) {
			total += 1.0
			reasons = append(reasons, "exact alertname match: "+an)
			break
		}
	}

	// 2. Keyword scan
	matchedKW := 0
	for _, kw := range rb.Keywords {
		if kw == "" {
			continue
		}
		if strings.Contains(haystack, strings.ToLower(kw)) {
			matchedKW++
		}
	}
	if matchedKW > 0 {
		kwScore := 0.2 * float64(matchedKW)
		if kwScore > 1.0 {
			kwScore = 1.0
		}
		total += kwScore
		reasons = append(reasons, keywordReason(matchedKW, len(rb.Keywords)))
	}

	// 3. Tag-vs-label scan
	matchedTags := matchTags(rb.Tags, q.Labels)
	if matchedTags > 0 {
		tagScore := 0.1 * float64(matchedTags)
		if tagScore > 0.5 {
			tagScore = 0.5
		}
		total += tagScore
		reasons = append(reasons, tagReason(matchedTags))
	}

	if len(reasons) == 0 {
		return 0, ""
	}
	return total, strings.Join(reasons, "; ")
}

// matchTags returns how many tags appear (substring, case-insensitive) in
// any label key or value. We scan keys too because a tag like "k8s" should
// match a label key like "kubernetes_pod_name" or "k8s_node".
func matchTags(tags []string, labels map[string]string) int {
	if len(tags) == 0 || len(labels) == 0 {
		return 0
	}
	matched := 0
	for _, tag := range tags {
		t := strings.ToLower(strings.TrimSpace(tag))
		if t == "" {
			continue
		}
		for k, v := range labels {
			if strings.Contains(strings.ToLower(k), t) ||
				strings.Contains(strings.ToLower(v), t) {
				matched++
				break // count each tag at most once
			}
		}
	}
	return matched
}

// buildHaystack constructs the lowercased blob of text we run keyword
// matches against. Annotation/label keys are excluded; their values carry
// the actual prose.
func buildHaystack(q Query) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(q.AlertName))
	b.WriteByte(' ')
	for _, v := range q.Labels {
		b.WriteString(strings.ToLower(v))
		b.WriteByte(' ')
	}
	for _, v := range q.Annotations {
		b.WriteString(strings.ToLower(v))
		b.WriteByte(' ')
	}
	return b.String()
}

func keywordReason(matched, total int) string {
	if total == 0 {
		return "keyword match"
	}
	return "keyword match (" + itoa(matched) + "/" + itoa(total) + ")"
}

func tagReason(matched int) string {
	if matched == 1 {
		return "1 tag matched alert labels"
	}
	return itoa(matched) + " tags matched alert labels"
}

// itoa is a tiny stdlib-free integer-to-string. We avoid strconv here only
// to keep imports minimal in this file; correctness matters, not perf.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// excerpt returns the snippet body, preferring frontmatter Summary when set
// and otherwise truncating Body to maxChars at a word boundary. The
// truncation is byte-counted, which is fine for ASCII/UTF-8 — we only need
// a soft cap, not exact precision.
func excerpt(rb *Runbook, maxChars int) string {
	if maxChars <= 0 {
		maxChars = 2000
	}

	// Prefer summary when it's set AND short — a long summary defeats the
	// point. If summary > maxChars we fall through to body truncation.
	if rb.Summary != "" && len(rb.Summary) <= maxChars {
		return rb.Summary
	}

	body := strings.TrimSpace(rb.Body)
	if len(body) <= maxChars {
		return body
	}

	// Truncate at last whitespace before maxChars to avoid splitting words
	// mid-token; fall back to a hard cut if no whitespace found.
	cut := body[:maxChars]
	if idx := strings.LastIndexAny(cut, " \n\t"); idx > maxChars/2 {
		cut = cut[:idx]
	}
	return strings.TrimSpace(cut) + "\n\n[...truncated]"
}
