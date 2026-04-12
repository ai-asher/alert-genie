package safety

// RiskLevel represents the risk level of a command.
type RiskLevel int

const (
	RiskLow      RiskLevel = 1
	RiskMedium   RiskLevel = 2
	RiskHigh     RiskLevel = 3
	RiskCritical RiskLevel = 4
)

// String returns the string representation of a RiskLevel.
func (r RiskLevel) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseRiskLevel parses a string into a RiskLevel.
// Unknown values are treated as critical for safety.
func ParseRiskLevel(s string) RiskLevel {
	switch s {
	case "low":
		return RiskLow
	case "medium":
		return RiskMedium
	case "high":
		return RiskHigh
	case "critical":
		return RiskCritical
	default:
		return RiskCritical
	}
}

// SafetyVerdict is the result of a command safety validation.
type SafetyVerdict struct {
	Allowed     bool
	RiskLevel   RiskLevel
	MatchedRule string
	Reason      string
}

// Command represents a command to be validated.
type Command struct {
	Raw         string
	CommandType string // "k8s" or "ssh"
	Target      string
	Namespace   string
}
