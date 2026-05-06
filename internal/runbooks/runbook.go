// Package runbooks implements a team-curated runbook knowledge base.
//
// Runbooks are markdown files on disk with optional YAML frontmatter. The
// loader scans a configured directory, parses frontmatter, and the retriever
// matches a runbook to an incoming alert via alertname/keyword/tag scoring.
// Matches are passed to the main analyzer prompt as authoritative guidance.
//
// Why this exists: historical incidents are evidence ("here's what happened
// before"), but runbooks are PROCEDURE ("here's the official way to handle
// this"). The analyzer treats runbooks with higher trust and prefers them
// over its own intuition or ranked historical incidents when both apply.
package runbooks

import "time"

// Runbook is a single loaded runbook document parsed from a markdown file.
// AlertNames and Keywords drive the retriever's scoring. Body is the full
// markdown body (frontmatter stripped) and is what gets truncated into a
// snippet at retrieval time.
type Runbook struct {
	// ID is a stable identifier — typically the file path relative to the
	// configured runbook directory.
	ID string
	// Title is the first H1 from the markdown body, or the filename stem
	// if no H1 is present.
	Title string
	// AlertNames lists alert names this runbook applies to. Populated from
	// frontmatter "alertnames" or derived from the filename when absent.
	AlertNames []string
	// Keywords are matched against alertname / labels / annotations text.
	// Populated from frontmatter "keywords" or auto-extracted from the title.
	Keywords []string
	// Tags are free-form labels (e.g. "k8s", "redis"). Used for tag-vs-label
	// matching during retrieval.
	Tags []string
	// Summary is an optional short description from frontmatter. Preferred
	// over Body for snippet excerpts when present.
	Summary string
	// Body is the markdown body with frontmatter stripped. Sent to the LLM
	// verbatim (truncated) — we deliberately don't render it.
	Body string
	// UpdatedAt is the file's mtime at load time. Useful for cache busting
	// and debugging "is the latest runbook deployed?" questions.
	UpdatedAt time.Time
}

// RunbookSnippet is the lean form passed to the analyzer prompt. Body is
// truncated; identifying fields point back at the source so the LLM (and
// humans reading logs) can find the full document.
type RunbookSnippet struct {
	// Title is the runbook title for display.
	Title string
	// Source is the runbook ID (file path) so users can find the original.
	Source string
	// RelevanceReason is a short human-readable explanation of why this
	// runbook was selected (e.g. "exact alertname match: HighMemoryUsage").
	RelevanceReason string
	// Excerpt is the truncated body or summary fed into the prompt. The
	// retriever caps this at ~2000 characters to keep prompt size bounded.
	Excerpt string
}
