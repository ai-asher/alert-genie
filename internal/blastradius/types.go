// Package blastradius computes objective impact metrics for healing commands.
//
// After the safety validator approves a HealingCommand, this package queries
// Prometheus for concrete signals about the resource being touched (replica
// count, traffic share, dependents) so the human approver can see the actual
// blast radius of running the command — not just the LLM's subjective risk
// label.
package blastradius

// Severity ordering used when comparing computed severity to the LLM-assigned
// risk level. Higher index means higher severity.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// FindingKind enumerates the categories of observations the assessor can emit.
const (
	FindingTraffic    = "traffic"
	FindingReplicas   = "replicas"
	FindingDownstream = "downstream"
	FindingNoData     = "no_data"
)

// Assessment is the per-command blast radius result.
type Assessment struct {
	// CommandID is the identifier of the HealingCommand this assessment refers
	// to. Callers should set this to whatever stable handle they use (e.g.
	// "<plan_id>:<step>"); the assessor itself only echoes back the value
	// supplied on the input Command.
	CommandID string

	// EstimatedReplicasAffected is the number of pods/instances the command
	// would touch (e.g. all replicas of a Deployment for a rollout restart).
	EstimatedReplicasAffected int

	// EstimatedTrafficShareBps is the share of total service traffic the
	// affected resource handles, expressed as a fraction in [0.0, 1.0].
	// (Despite the field name, this is a fraction, not basis points — the
	// "Bps" suffix matches the design contract requested by the caller.)
	EstimatedTrafficShareBps float64

	// DependentServices lists services that consume the affected one and
	// would be impacted if it went down.
	DependentServices []string

	// OverallSeverity is the computed severity ("low", "medium", "high",
	// "critical") derived from the signals collected.
	OverallSeverity string

	// Confidence is in [0.0, 1.0]; lowered when data was missing or queries
	// failed.
	Confidence float64

	// Findings are human-readable observations rendered on the approval card.
	Findings []Finding

	// SuggestedRiskUpgrade is non-empty when the computed severity exceeds the
	// LLM-assigned risk level on the input command, e.g. "high" when the LLM
	// said "low" but blast radius shows critical traffic exposure.
	SuggestedRiskUpgrade string
}

// Finding is a single observation, e.g. "deployment user-api currently
// handles 4500 req/s; scaling to 0 would drop the entire service".
type Finding struct {
	// Kind is one of the Finding* constants ("traffic", "replicas",
	// "downstream", "no_data").
	Kind string
	// Message is the human-readable text shown to the approver.
	Message string
}

// Command is the input view passed to the assessor. It mirrors the fields of
// analyzer.HealingCommand that the assessor needs, defined here to avoid an
// import cycle between blastradius and analyzer.
type Command struct {
	// ID is a stable identifier for the command, echoed back in
	// Assessment.CommandID.
	ID string
	// Step is the 1-based step index in the healing plan.
	Step int
	// CommandType is "k8s" or "ssh".
	CommandType string
	// Target is the cluster name (k8s) or host (ssh) the command runs on.
	Target string
	// Namespace is the Kubernetes namespace, when applicable.
	Namespace string
	// Command is the raw command string to be executed.
	Command string
	// Args is an optional structured map of arguments parsed by the planner.
	Args map[string]string
	// LLMRiskLevel is the risk level assigned by the LLM; the assessor may
	// suggest an upgrade if computed severity exceeds it.
	LLMRiskLevel string
}

// severityRank maps a severity string to an integer rank for comparisons.
// Unknown values rank as 0 (below low) so they never trigger an upgrade.
func severityRank(s string) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}
