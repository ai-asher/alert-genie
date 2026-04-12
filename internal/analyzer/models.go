package analyzer

import (
	"time"

	"github.com/alert-genie/alert-genie/internal/metrics"
)

// Mode controls whether the analyzer can suggest healing actions.
type Mode string

const (
	// ModeReadOnly instructs the analyzer to only produce analysis, no healing plan.
	ModeReadOnly Mode = "readonly"
	// ModeHealing instructs the analyzer to produce analysis with a healing plan.
	ModeHealing Mode = "healing"
)

// AnalysisRequest contains all context needed for the LLM to analyze an alert.
type AnalysisRequest struct {
	AlertName    string
	AlertStatus  string
	Severity     string
	Labels       map[string]string
	Annotations  map[string]string
	StartsAt     time.Time
	Duration     time.Duration
	GroupKey     string
	TotalInGroup int
	CommonLabels map[string]string
	GeneratorURL string
	Metrics      []metrics.MetricSeries
	Topology     *TopologyContext
	Mode         Mode
}

// TopologyContext holds service topology info for the prompt.
type TopologyContext struct {
	ServiceName       string
	OwnerTeam         string
	Tier              string
	Dependencies      []TopologyEntry
	Downstream        []TopologyEntry
	KnownFailureModes []FailureMode
}

// TopologyEntry describes a related service in the topology graph.
type TopologyEntry struct {
	Name                string
	Type                string
	Description         string
	ImpactIfUnavailable string
}

// FailureMode describes a known failure pattern for the service.
type FailureMode struct {
	Mode              string
	TypicalCause      string
	TypicalResolution string
}

// AnalysisResult is the structured output from the LLM analysis.
type AnalysisResult struct {
	AlertID          string          `json:"alert_id"`
	Summary          string          `json:"summary"`
	RootCause        string          `json:"root_cause"`
	Severity         string          `json:"severity"`
	Impact           string          `json:"impact"`
	AffectedServices []string        `json:"affected_services"`
	MetricInsights   []MetricInsight `json:"metric_insights"`
	Recommendations  []string        `json:"recommendations"`
	HealingPlan      *HealingPlan    `json:"healing_plan,omitempty"`
	Confidence       float64         `json:"confidence"`
	AnalyzedAt       time.Time       `json:"analyzed_at"`
	ModelUsed        string          `json:"model_used"`
	TokensUsed       TokenUsage      `json:"tokens_used"`
}

// MetricInsight summarises a single metric trend observation.
type MetricInsight struct {
	MetricName  string `json:"metric_name"`
	Trend       string `json:"trend"`
	Observation string `json:"observation"`
}

// TokenUsage reports API token consumption.
type TokenUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// HealingPlan describes an automated remediation sequence.
type HealingPlan struct {
	PlanID        string           `json:"plan_id"`
	Description   string           `json:"description"`
	Commands      []HealingCommand `json:"commands"`
	RollbackPlan  []HealingCommand `json:"rollback_plan"`
	EstimatedTime string           `json:"estimated_time"`
	OverallRisk   string           `json:"overall_risk"`
	Preconditions []string         `json:"preconditions"`
	Warnings      []string         `json:"warnings"`
}

// HealingCommand is a single step in a healing or rollback plan.
type HealingCommand struct {
	Step          int               `json:"step"`
	Description   string            `json:"description"`
	CommandType   string            `json:"command_type"`
	Target        string            `json:"target"`
	Namespace     string            `json:"namespace,omitempty"`
	Command       string            `json:"command"`
	Args          map[string]string `json:"args,omitempty"`
	RiskLevel     string            `json:"risk_level"`
	ImpactSummary string            `json:"impact_summary"`
	TimeoutSec    int               `json:"timeout_seconds"`
	WaitAfterSec  int               `json:"wait_after_seconds"`
	VerifyCommand string            `json:"verify_command,omitempty"`
}
