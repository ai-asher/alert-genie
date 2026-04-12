package safety

import "regexp"

// WhitelistRule defines an allowed command pattern.
type WhitelistRule struct {
	Name        string
	Pattern     *regexp.Regexp
	CommandType string // "k8s", "ssh", or "" for any
	RiskLevel   RiskLevel
	Description string
}

// BlacklistRule defines a forbidden command pattern.
type BlacklistRule struct {
	Pattern *regexp.Regexp
	Reason  string
}

// DefaultWhitelist returns the default set of whitelisted command patterns.
func DefaultWhitelist() []WhitelistRule {
	return []WhitelistRule{
		// K8s read-only commands (Low risk)
		{
			Name:        "k8s-get",
			Pattern:     regexp.MustCompile(`^kubectl\s+get\s+`),
			CommandType: "k8s",
			RiskLevel:   RiskLow,
			Description: "Kubernetes get resources",
		},
		{
			Name:        "k8s-describe",
			Pattern:     regexp.MustCompile(`^kubectl\s+describe\s+`),
			CommandType: "k8s",
			RiskLevel:   RiskLow,
			Description: "Kubernetes describe resources",
		},
		{
			Name:        "k8s-logs",
			Pattern:     regexp.MustCompile(`^kubectl\s+logs\s+`),
			CommandType: "k8s",
			RiskLevel:   RiskLow,
			Description: "Kubernetes view logs",
		},
		// K8s mutating commands (Medium risk)
		{
			Name:        "k8s-rollout-restart",
			Pattern:     regexp.MustCompile(`^kubectl\s+rollout\s+restart\s+(deployment|daemonset|statefulset)\s+\S+`),
			CommandType: "k8s",
			RiskLevel:   RiskMedium,
			Description: "Kubernetes rollout restart",
		},
		{
			Name:        "k8s-delete-pod",
			Pattern:     regexp.MustCompile(`^kubectl\s+delete\s+pod\s+\S+`),
			CommandType: "k8s",
			RiskLevel:   RiskMedium,
			Description: "Kubernetes delete specific pod",
		},
		// K8s high-risk commands (High risk)
		{
			Name:        "k8s-scale",
			Pattern:     regexp.MustCompile(`^kubectl\s+scale\s+(deployment|statefulset|replicaset)\s+\S+\s+--replicas=\d+`),
			CommandType: "k8s",
			RiskLevel:   RiskHigh,
			Description: "Kubernetes scale resources",
		},
		{
			Name:        "k8s-rollback",
			Pattern:     regexp.MustCompile(`^kubectl\s+rollout\s+undo\s+(deployment|daemonset|statefulset)\s+\S+`),
			CommandType: "k8s",
			RiskLevel:   RiskHigh,
			Description: "Kubernetes rollback deployment",
		},
		{
			Name:        "k8s-patch",
			Pattern:     regexp.MustCompile(`^kubectl\s+patch\s+(deployment|service|configmap|ingress)\s+\S+`),
			CommandType: "k8s",
			RiskLevel:   RiskHigh,
			Description: "Kubernetes patch resource",
		},
		// SSH read-only commands (Low risk)
		{
			Name:        "ssh-systemctl-status",
			Pattern:     regexp.MustCompile(`^systemctl\s+status\s+\S+`),
			CommandType: "ssh",
			RiskLevel:   RiskLow,
			Description: "Check service status",
		},
		{
			Name:        "ssh-df",
			Pattern:     regexp.MustCompile(`^df\s+`),
			CommandType: "ssh",
			RiskLevel:   RiskLow,
			Description: "Check disk space",
		},
		{
			Name:        "ssh-du",
			Pattern:     regexp.MustCompile(`^du\s+`),
			CommandType: "ssh",
			RiskLevel:   RiskLow,
			Description: "Check directory size",
		},
		{
			Name:        "ssh-journalctl",
			Pattern:     regexp.MustCompile(`^journalctl\s+`),
			CommandType: "ssh",
			RiskLevel:   RiskLow,
			Description: "View journal logs",
		},
		// SSH mutating commands (Medium risk)
		{
			Name:        "ssh-systemctl-restart",
			Pattern:     regexp.MustCompile(`^systemctl\s+restart\s+\S+`),
			CommandType: "ssh",
			RiskLevel:   RiskMedium,
			Description: "Restart a service",
		},
		{
			Name:        "ssh-nginx-reload",
			Pattern:     regexp.MustCompile(`^(nginx\s+-s\s+reload|systemctl\s+reload\s+nginx)`),
			CommandType: "ssh",
			RiskLevel:   RiskMedium,
			Description: "Reload nginx configuration",
		},
		{
			Name:        "ssh-kill",
			Pattern:     regexp.MustCompile(`^kill\s+(-\d+\s+)?\d+$`),
			CommandType: "ssh",
			RiskLevel:   RiskMedium,
			Description: "Kill a specific process by PID",
		},
		// SSH high-risk commands (High risk)
		{
			Name:        "ssh-find-delete",
			Pattern:     regexp.MustCompile(`^find\s+\S+\s+.*-delete$`),
			CommandType: "ssh",
			RiskLevel:   RiskHigh,
			Description: "Find and delete files",
		},
		{
			Name:        "ssh-rm-logfile",
			Pattern:     regexp.MustCompile(`^rm\s+(-f\s+)?\S+\.(log|tmp|old|bak)$`),
			CommandType: "ssh",
			RiskLevel:   RiskHigh,
			Description: "Remove specific log/temp files",
		},
	}
}

// DefaultBlacklist returns the default set of blacklisted command patterns.
func DefaultBlacklist() []BlacklistRule {
	return []BlacklistRule{
		{
			Pattern: regexp.MustCompile(`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|(-[a-zA-Z]*f[a-zA-Z]*r))\s`),
			Reason:  "recursive force delete is too dangerous",
		},
		{
			Pattern: regexp.MustCompile(`rm\s+.*\*`),
			Reason:  "wildcard delete is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`\bmkfs\b`),
			Reason:  "filesystem formatting is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`\bdd\s+`),
			Reason:  "raw disk operations are forbidden",
		},
		{
			Pattern: regexp.MustCompile(`chmod\s+777\b`),
			Reason:  "world-writable permissions are forbidden",
		},
		{
			Pattern: regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\b`),
			Reason:  "DROP statements are forbidden",
		},
		{
			Pattern: regexp.MustCompile(`(?i)\bTRUNCATE\s+TABLE\b`),
			Reason:  "TRUNCATE statements are forbidden",
		},
		{
			Pattern: regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\S+\s*$`),
			Reason:  "unqualified DELETE (no WHERE clause) is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`(password|secret|token|api.?key)\s*=\s*\S+`),
			Reason:  "embedding credentials in commands is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`curl\s+.*\|\s*sh`),
			Reason:  "piping curl to shell is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`kubectl\s+delete\s+(ns|namespace)\s+`),
			Reason:  "deleting namespaces is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`kubectl\s+delete\s+.*--all\b`),
			Reason:  "kubectl delete --all is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`kubectl\s+exec\s+`),
			Reason:  "kubectl exec is forbidden for automated healing",
		},
		{
			Pattern: regexp.MustCompile(`\biptables\b`),
			Reason:  "iptables modification is forbidden",
		},
		{
			Pattern: regexp.MustCompile(`\b(shutdown|reboot)\b`),
			Reason:  "system shutdown/reboot is forbidden",
		},
	}
}
