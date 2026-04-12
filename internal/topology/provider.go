package topology

// ServiceTopology holds the topology information for a service.
type ServiceTopology struct {
	ServiceName       string        `yaml:"name" json:"name"`
	OwnerTeam         string        `yaml:"owner_team" json:"owner_team"`
	Tier              string        `yaml:"tier" json:"tier"`
	Dependencies      []Dependency  `yaml:"dependencies" json:"dependencies"`
	Downstream        []Downstream  `yaml:"downstream" json:"downstream"`
	KnownFailureModes []FailureMode `yaml:"known_failure_modes" json:"known_failure_modes"`
	CustomQueries     []string      `yaml:"custom_queries" json:"custom_queries"`
}

type Dependency struct {
	Name        string `yaml:"name" json:"name"`
	Type        string `yaml:"type" json:"type"`
	Description string `yaml:"description" json:"description"`
}

type Downstream struct {
	Name                string `yaml:"name" json:"name"`
	ImpactIfUnavailable string `yaml:"impact_if_unavailable" json:"impact_if_unavailable"`
}

type FailureMode struct {
	Mode              string `yaml:"mode" json:"mode"`
	TypicalCause      string `yaml:"typical_cause" json:"typical_cause"`
	TypicalResolution string `yaml:"typical_resolution" json:"typical_resolution"`
}

// Provider looks up topology for a given service name.
type Provider interface {
	Get(serviceName string) *ServiceTopology
}
