// Package correlation groups simultaneously-firing alerts that likely share a
// root cause so that a single Claude analysis and a single Lark card can cover
// the whole cluster, instead of one analysis per dependent alert.
//
// The package is deliberately decoupled from the alert and pipeline packages
// to avoid import cycles: callers map their own alert representation onto the
// correlation.Alert struct at the call site.
package correlation

import "time"

// Group is a set of correlated alerts believed to share a root cause.
//
// A Group always carries exactly one Primary alert. Dependents may be empty —
// in that case the group represents a single isolated alert and downstream
// processing should treat it the same as the pre-correlation flow.
type Group struct {
	// GroupID uniquely identifies this correlation group. It is generated at
	// flush time and is not stable across restarts.
	GroupID string

	// Primary is the alert designated as the most likely root cause within
	// the cluster. See package docs for the selection heuristic.
	Primary Alert

	// Dependents are the other alerts in the cluster, ordered as they were
	// observed in the buffer. Empty for solo groups.
	Dependents []Alert

	// CorrelationReason is a short human-readable explanation of why these
	// alerts were grouped, e.g. "all share service=user-api" or
	// "primary fired 12s before dependents".
	CorrelationReason string

	// DetectedAt is the wall-clock time the group was emitted.
	DetectedAt time.Time
}

// Alert is the correlation-layer view of a persisted alert.
//
// It mirrors the subset of alert.Alert + alert.PersistedAlert fields the
// correlator needs, but lives in this package so the correlation logic can be
// imported from anywhere (including pipeline) without creating cycles. The
// caller is expected to populate it from its own alert representation.
type Alert struct {
	// ID is the persisted alert UUID (alerts.id in the store).
	ID string

	// Fingerprint is the Alertmanager fingerprint, used for traceability.
	Fingerprint string

	// AlertName is the alertname label (e.g. "HighCPU").
	AlertName string

	// Severity is the severity label (e.g. "critical", "warning").
	Severity string

	// Service is the alert's service identity, derived by the caller from
	// labels["service"] or labels["job"]. May be empty.
	Service string

	// Namespace is labels["namespace"] when present. May be empty.
	Namespace string

	// Instance is labels["instance"] when present. May be empty.
	Instance string

	// Labels is the full label set, kept for downstream rendering.
	Labels map[string]string

	// Annotations is the full annotation set, kept for downstream rendering.
	Annotations map[string]string

	// StartsAt is the alert's firing-since timestamp from Alertmanager.
	// The correlator uses this to pick the earliest-firing alert as primary.
	StartsAt time.Time
}
