package config

import (
	"fmt"
)

func validate(cfg *Config) error {
	if cfg.Mode != "readonly" && cfg.Mode != "healing" {
		return fmt.Errorf("mode must be 'readonly' or 'healing', got %q", cfg.Mode)
	}

	if cfg.Prometheus.Address == "" {
		return fmt.Errorf("prometheus.address is required")
	}

	if cfg.Claude.BaseURL == "" {
		return fmt.Errorf("claude.base_url is required")
	}
	if cfg.Claude.APIKey == "" {
		return fmt.Errorf("claude.api_key is required (set CLAUDE_API_KEY env var)")
	}
	if cfg.Claude.Model == "" {
		return fmt.Errorf("claude.model is required")
	}

	if cfg.Lark.AppID == "" {
		return fmt.Errorf("lark.app_id is required")
	}
	if cfg.Lark.AppSecret == "" {
		return fmt.Errorf("lark.app_secret is required")
	}
	if cfg.Lark.AlertChatID == "" {
		return fmt.Errorf("lark.alert_chat_id is required")
	}

	if cfg.Store.Driver != "sqlite" && cfg.Store.Driver != "postgres" {
		return fmt.Errorf("store.driver must be 'sqlite' or 'postgres', got %q", cfg.Store.Driver)
	}
	if cfg.Store.Driver == "postgres" && cfg.Store.PostgresDSN == "" {
		return fmt.Errorf("store.postgres_dsn is required when driver is 'postgres'")
	}

	if cfg.Mode == "healing" {
		if len(cfg.Kubernetes.Clusters) == 0 && len(cfg.SSH.Targets) == 0 {
			return fmt.Errorf("healing mode requires at least one kubernetes cluster or ssh target")
		}
	}

	for i, c := range cfg.Kubernetes.Clusters {
		if c.Name == "" {
			return fmt.Errorf("kubernetes.clusters[%d].name is required", i)
		}
		if !c.InCluster && c.KubeconfigPath == "" {
			return fmt.Errorf("kubernetes.clusters[%d] must set either in_cluster or kubeconfig_path", i)
		}
	}

	for i, t := range cfg.SSH.Targets {
		if t.Name == "" {
			return fmt.Errorf("ssh.targets[%d].name is required", i)
		}
		if t.Host == "" {
			return fmt.Errorf("ssh.targets[%d].host is required", i)
		}
		if t.User == "" {
			return fmt.Errorf("ssh.targets[%d].user is required", i)
		}
		if t.PrivateKeyPath == "" {
			return fmt.Errorf("ssh.targets[%d].private_key_path is required", i)
		}
		if t.Port == 0 {
			cfg.SSH.Targets[i].Port = 22
		}
	}

	return nil
}
