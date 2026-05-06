package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Mode         string             `yaml:"mode"` // "readonly" or "healing"
	Alertmanager AlertmanagerConfig `yaml:"alertmanager"`
	Prometheus   PrometheusConfig   `yaml:"prometheus"`
	Claude       ClaudeConfig       `yaml:"claude"`
	Lark         LarkConfig         `yaml:"lark"`
	Kubernetes   KubernetesConfig   `yaml:"kubernetes"`
	SSH          SSHConfig          `yaml:"ssh"`
	Safety       SafetyConfig       `yaml:"safety"`
	Approval     ApprovalConfig     `yaml:"approval"`
	Store        StoreConfig        `yaml:"store"`
	Topology     TopologyConfig     `yaml:"topology"`
	Historical   HistoricalConfig   `yaml:"historical"`
	Runbooks     RunbooksConfig     `yaml:"runbooks"`
	Correlation  CorrelationConfig  `yaml:"correlation"`
	BlastRadius  BlastRadiusConfig  `yaml:"blast_radius"`
	Logging      LoggingConfig      `yaml:"logging"`
}

// BlastRadiusConfig governs the per-command blast radius assessor that runs
// after safety validation passes. It is disabled by default; enabling it
// causes the pipeline to query Prometheus for replica counts, traffic share,
// and topology dependents before rendering the approval card.
type BlastRadiusConfig struct {
	// Enabled gates the entire feature. When false the pipeline skips
	// assessment and the approval card omits the impact section.
	Enabled bool `yaml:"enabled"`
	// QueryTimeout caps each individual Prometheus query. Default 5s.
	QueryTimeout time.Duration `yaml:"query_timeout"`
	// HighTrafficThreshold (0.0-1.0) is the share of cluster traffic at or
	// above which severity is computed as "high". Default 0.5.
	HighTrafficThreshold float64 `yaml:"high_traffic_threshold"`
	// CriticalTrafficThreshold (0.0-1.0) is the share at or above which
	// severity is computed as "critical". Default 0.8.
	CriticalTrafficThreshold float64 `yaml:"critical_traffic_threshold"`
	// AutoUpgradeRiskLevel, when true, lets the pipeline overwrite a
	// command's RiskLevel with the assessor's SuggestedRiskUpgrade.
	// Default false: the upgrade is surfaced on the card but the LLM-
	// assigned level is preserved for downstream escalation rules.
	AutoUpgradeRiskLevel bool `yaml:"auto_upgrade_risk_level"`
}

type ServerConfig struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
}

type AlertmanagerConfig struct {
	DedupWindow    time.Duration `yaml:"dedup_window"`
	SeverityFilter []string      `yaml:"severity_filter"`
}

type PrometheusConfig struct {
	Address              string              `yaml:"address"`
	QueryWindow          time.Duration       `yaml:"query_window"`
	MaxConcurrentQueries int                 `yaml:"max_concurrent_queries"`
	QueryTimeout         time.Duration       `yaml:"query_timeout"`
	AlertQueries         map[string][]string `yaml:"alert_queries"`
}

type ClaudeConfig struct {
	BaseURL      string        `yaml:"base_url"`
	APIKey       string        `yaml:"api_key"`
	Model        string        `yaml:"model"`
	MaxTokens    int           `yaml:"max_tokens"`
	Temperature  float64       `yaml:"temperature"`
	Timeout      time.Duration `yaml:"timeout"`
	MaxRetries   int           `yaml:"max_retries"`
	RetryBackoff time.Duration `yaml:"retry_backoff"`
}

type LarkConfig struct {
	AppID             string `yaml:"app_id"`
	AppSecret         string `yaml:"app_secret"`
	VerificationToken string `yaml:"verification_token"`
	EncryptionKey     string `yaml:"encryption_key"`
	AlertChatID       string `yaml:"alert_chat_id"`
	CallbackURL       string `yaml:"callback_url"`
	BotOpenID         string `yaml:"bot_open_id"`  // required when ChatEnabled
	BotName           string `yaml:"bot_name"`     // optional fallback for @ detection
	ChatEnabled       bool   `yaml:"chat_enabled"` // enable @Bot multi-turn conversations
}

type KubernetesConfig struct {
	Clusters []ClusterConfig `yaml:"clusters"`
}

type ClusterConfig struct {
	Name              string   `yaml:"name"`
	KubeconfigPath    string   `yaml:"kubeconfig_path"`
	InCluster         bool     `yaml:"in_cluster"`
	Context           string   `yaml:"context"`
	AllowedNamespaces []string `yaml:"allowed_namespaces"`
	QPS               float32  `yaml:"qps"`
	Burst             int      `yaml:"burst"`
}

type SSHConfig struct {
	Targets []SSHTarget `yaml:"targets"`
}

type SSHTarget struct {
	Name                    string   `yaml:"name"`
	Host                    string   `yaml:"host"`
	Port                    int      `yaml:"port"`
	User                    string   `yaml:"user"`
	PrivateKeyPath          string   `yaml:"private_key_path"`
	BastionHost             string   `yaml:"bastion_host"`
	BastionUser             string   `yaml:"bastion_user"`
	BastionKeyPath          string   `yaml:"bastion_key_path"`
	AllowedCommandsOverride []string `yaml:"allowed_commands_override"`
}

type SafetyConfig struct {
	ExtraWhitelist     []WhitelistEntry `yaml:"extra_whitelist"`
	ExtraBlacklist     []BlacklistEntry `yaml:"extra_blacklist"`
	Escalation         EscalationConfig `yaml:"escalation"`
	MaxCommandsPerPlan int              `yaml:"max_commands_per_plan"`
	MaxPlanTimeout     time.Duration    `yaml:"max_plan_timeout"`
}

type WhitelistEntry struct {
	Name        string `yaml:"name"`
	Pattern     string `yaml:"pattern"`
	CommandType string `yaml:"command_type"`
	RiskLevel   string `yaml:"risk_level"`
	Description string `yaml:"description"`
}

type BlacklistEntry struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

type EscalationConfig struct {
	Low      string `yaml:"low"`
	Medium   string `yaml:"medium"`
	High     string `yaml:"high"`
	Critical string `yaml:"critical"`
}

type ApprovalConfig struct {
	TTL                 time.Duration `yaml:"ttl"`
	ExpireCheckInterval time.Duration `yaml:"expire_check_interval"`
}

type StoreConfig struct {
	Driver          string        `yaml:"driver"` // "sqlite" or "postgres"
	SQLitePath      string        `yaml:"sqlite_path"`
	PostgresDSN     string        `yaml:"postgres_dsn"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

type TopologyConfig struct {
	ConfigPath string `yaml:"config_path"`
}

// HistoricalConfig controls the historical incident retriever.
type HistoricalConfig struct {
	Enabled             bool `yaml:"enabled"`                // master switch, default false
	CandidatePoolSize   int  `yaml:"candidate_pool_size"`    // SQL pre-filter cap, default 50
	TopK                int  `yaml:"top_k"`                  // # incidents fed into main prompt, default 3
	LookbackDays        int  `yaml:"lookback_days"`          // freshness window, default 90
	MinCandidatesForLLM int  `yaml:"min_candidates_for_llm"` // skip ranker below this, default 2
}

// RunbooksConfig controls the runbook knowledge base — markdown playbooks
// loaded from disk and matched to alerts to feed authoritative procedure
// snippets into the analyzer prompt.
type RunbooksConfig struct {
	// Enabled is the master switch. When false the retriever isn't built
	// and the prompt's RUNBOOKS block stays empty.
	Enabled bool `yaml:"enabled"`
	// Directory is the absolute or working-dir-relative path to a directory
	// containing .md runbook files. The loader walks it recursively.
	Directory string `yaml:"directory"`
	// ReloadInterval is how often the store re-scans Directory for changes.
	// Set to 0 to use the 5-minute default.
	ReloadInterval time.Duration `yaml:"reload_interval"`
	// TopK is the maximum number of runbooks fed to the analyzer prompt
	// per alert. Default 2 — runbooks are authoritative, so we don't need
	// many.
	TopK int `yaml:"top_k"`
}

// CorrelationConfig controls the alert-correlation buffer that groups
// simultaneously-firing alerts so a single Claude analysis (and one Lark
// card) covers the whole cluster.
type CorrelationConfig struct {
	// Enabled is the master switch. When false the pipeline runs in the
	// pre-correlation per-alert flow, preserving today's behaviour exactly.
	Enabled bool `yaml:"enabled"`
	// Window is how long incoming alerts wait in the buffer before being
	// grouped and dispatched. Larger windows catch more correlated alerts
	// at the cost of higher per-alert latency. Default 30s.
	Window time.Duration `yaml:"window"`
	// MaxGroupSize is a hard cap on the number of alerts in a single group;
	// oversize clusters are split into chunks. Default 50, set to 0 to
	// disable the cap.
	MaxGroupSize int `yaml:"max_group_size"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // json, text
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	data = expandEnvVars(data)

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	setDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func expandEnvVars(raw []byte) []byte {
	return envVarPattern.ReplaceAllFunc(raw, func(match []byte) []byte {
		varName := string(match[2 : len(match)-1])
		if val, ok := os.LookupEnv(varName); ok {
			return []byte(val)
		}
		return match
	})
}

func setDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 30 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 60 * time.Second
	}
	if cfg.Server.ShutdownTimeout == 0 {
		cfg.Server.ShutdownTimeout = 15 * time.Second
	}
	if cfg.Mode == "" {
		cfg.Mode = "readonly"
	}
	if cfg.Alertmanager.DedupWindow == 0 {
		cfg.Alertmanager.DedupWindow = 5 * time.Minute
	}
	if cfg.Prometheus.QueryWindow == 0 {
		cfg.Prometheus.QueryWindow = 30 * time.Minute
	}
	if cfg.Prometheus.MaxConcurrentQueries == 0 {
		cfg.Prometheus.MaxConcurrentQueries = 5
	}
	if cfg.Prometheus.QueryTimeout == 0 {
		cfg.Prometheus.QueryTimeout = 15 * time.Second
	}
	if cfg.Claude.MaxTokens == 0 {
		cfg.Claude.MaxTokens = 4096
	}
	if cfg.Claude.Temperature == 0 {
		cfg.Claude.Temperature = 0.1
	}
	if cfg.Claude.Timeout == 0 {
		cfg.Claude.Timeout = 60 * time.Second
	}
	if cfg.Claude.MaxRetries == 0 {
		cfg.Claude.MaxRetries = 2
	}
	if cfg.Claude.RetryBackoff == 0 {
		cfg.Claude.RetryBackoff = 2 * time.Second
	}
	if cfg.Safety.MaxCommandsPerPlan == 0 {
		cfg.Safety.MaxCommandsPerPlan = 10
	}
	if cfg.Safety.MaxPlanTimeout == 0 {
		cfg.Safety.MaxPlanTimeout = 10 * time.Minute
	}
	if cfg.Safety.Escalation.Low == "" {
		cfg.Safety.Escalation.Low = "auto_approve_with_notify"
	}
	if cfg.Safety.Escalation.Medium == "" {
		cfg.Safety.Escalation.Medium = "single_approval"
	}
	if cfg.Safety.Escalation.High == "" {
		cfg.Safety.Escalation.High = "single_approval_with_warning"
	}
	if cfg.Safety.Escalation.Critical == "" {
		cfg.Safety.Escalation.Critical = "blocked"
	}
	if cfg.Approval.TTL == 0 {
		cfg.Approval.TTL = 30 * time.Minute
	}
	if cfg.Approval.ExpireCheckInterval == 0 {
		cfg.Approval.ExpireCheckInterval = 5 * time.Minute
	}
	if cfg.Store.Driver == "" {
		cfg.Store.Driver = "sqlite"
	}
	if cfg.Store.SQLitePath == "" {
		cfg.Store.SQLitePath = "./data/alert-genie.db"
	}
	if cfg.Store.MaxOpenConns == 0 {
		cfg.Store.MaxOpenConns = 10
	}
	if cfg.Store.MaxIdleConns == 0 {
		cfg.Store.MaxIdleConns = 5
	}
	if cfg.Store.ConnMaxLifetime == 0 {
		cfg.Store.ConnMaxLifetime = time.Hour
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}
	// Historical retriever defaults (only applied when enabled)
	if cfg.Historical.CandidatePoolSize == 0 {
		cfg.Historical.CandidatePoolSize = 50
	}
	if cfg.Historical.TopK == 0 {
		cfg.Historical.TopK = 3
	}
	if cfg.Historical.LookbackDays == 0 {
		cfg.Historical.LookbackDays = 90
	}
	if cfg.Historical.MinCandidatesForLLM == 0 {
		cfg.Historical.MinCandidatesForLLM = 2
	}
	// Runbook KB defaults (only applied when enabled)
	if cfg.Runbooks.ReloadInterval == 0 {
		cfg.Runbooks.ReloadInterval = 5 * time.Minute
	}
	if cfg.Runbooks.TopK == 0 {
		cfg.Runbooks.TopK = 2
	}
	// Correlation defaults (only applied when enabled)
	if cfg.Correlation.Window == 0 {
		cfg.Correlation.Window = 30 * time.Second
	}
	if cfg.Correlation.MaxGroupSize == 0 {
		cfg.Correlation.MaxGroupSize = 50
	}
	// Blast radius defaults (only meaningful when enabled)
	if cfg.BlastRadius.QueryTimeout == 0 {
		cfg.BlastRadius.QueryTimeout = 5 * time.Second
	}
	if cfg.BlastRadius.HighTrafficThreshold == 0 {
		cfg.BlastRadius.HighTrafficThreshold = 0.5
	}
	if cfg.BlastRadius.CriticalTrafficThreshold == 0 {
		cfg.BlastRadius.CriticalTrafficThreshold = 0.8
	}
}
