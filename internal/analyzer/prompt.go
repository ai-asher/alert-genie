package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

const systemPrompt = `You are an expert SRE / on-call engineer AI assistant. Your job is to analyze alerts, correlate metric data, and provide actionable insights.

Rules:
1. Be concise and precise. Focus on actionable root cause analysis.
2. When metric data is provided, look for correlations between metrics and the alert.
3. Consider the service topology to assess blast radius and downstream impact.
4. Severity assessment must consider business impact, not just technical metrics.
5. Recommendations must be specific and ordered by priority.
6. In healing mode, only suggest commands from the ALLOWED COMMAND VOCABULARY.
7. Always output valid JSON matching the REQUIRED OUTPUT SCHEMA exactly.`

var userPromptTemplate = template.Must(
	template.New("user_prompt").Funcs(template.FuncMap{
		"json": func(v any) string {
			b, err := json.Marshal(v)
			if err != nil {
				return fmt.Sprintf("%q", fmt.Sprintf("json marshal error: %v", err))
			}
			return string(b)
		},
		"upper": strings.ToUpper,
	}).Parse(userPromptRaw),
)

const userPromptRaw = `## ALERT DETAILS

- **Alert Name:** {{ .AlertName }}
- **Status:** {{ .AlertStatus }}
- **Severity:** {{ .Severity }}
- **Firing Since:** {{ .StartsAt.Format "2006-01-02T15:04:05Z07:00" }}
- **Duration:** {{ .Duration }}
- **Group Key:** {{ .GroupKey }}
- **Alerts in Group:** {{ .TotalInGroup }}
- **Generator URL:** {{ .GeneratorURL }}

**Labels:**
{{ json .Labels }}

**Annotations:**
{{ json .Annotations }}

**Common Labels:**
{{ json .CommonLabels }}

## PROMETHEUS METRIC TRENDS
{{ if .Metrics }}{{ range .Metrics }}
- {{ .Summary }}
{{ end }}{{ else }}
No metric data available.
{{ end }}

## SYSTEM TOPOLOGY
{{ if .Topology }}
- **Service:** {{ .Topology.ServiceName }}
- **Owner Team:** {{ .Topology.OwnerTeam }}
- **Tier:** {{ .Topology.Tier }}

**Dependencies (upstream):**
{{ range .Topology.Dependencies }}- {{ .Name }} ({{ .Type }}): {{ .Description }}. Impact if unavailable: {{ .ImpactIfUnavailable }}
{{ end }}
**Downstream (consumers):**
{{ range .Topology.Downstream }}- {{ .Name }} ({{ .Type }}): {{ .Description }}. Impact if unavailable: {{ .ImpactIfUnavailable }}
{{ end }}
**Known Failure Modes:**
{{ range .Topology.KnownFailureModes }}- {{ .Mode }}: cause={{ .TypicalCause }}, resolution={{ .TypicalResolution }}
{{ end }}{{ else }}
No topology information available.
{{ end }}

## MODE

Current mode: **{{ upper (print .Mode) }}**
{{ if eq (print .Mode) "healing" }}
You MUST include a healing_plan in your response.

### ALLOWED COMMAND VOCABULARY

Only the following command types may appear in healing_plan.commands:
- kubectl_rollout_restart: restart a deployment (args: deployment, namespace)
- kubectl_scale: scale a deployment (args: deployment, namespace, replicas)
- kubectl_delete_pod: delete a pod to force reschedule (args: pod, namespace)
- kubectl_cordon: mark node unschedulable (args: node)
- kubectl_uncordon: mark node schedulable (args: node)
- ssh_exec: execute a command via SSH (args: target, command)
- http_request: send an HTTP request (args: method, url, body)
{{ else }}
Read-only mode: do NOT include a healing_plan in your response.
{{ end }}

## REQUIRED OUTPUT SCHEMA

Respond with ONLY a JSON object matching this schema (no markdown fencing, no explanation outside the JSON):
{
  "alert_id": "<string: unique identifier for this analysis>",
  "summary": "<string: 1-2 sentence summary>",
  "root_cause": "<string: most likely root cause>",
  "severity": "<string: critical|high|medium|low>",
  "impact": "<string: business and technical impact>",
  "affected_services": ["<string: list of affected services>"],
  "metric_insights": [{"metric_name": "<string>", "trend": "<string>", "observation": "<string>"}],
  "recommendations": ["<string: ordered list of actions>"],
  {{ if eq (print .Mode) "healing" }}"healing_plan": {
    "plan_id": "<string>",
    "description": "<string>",
    "commands": [{"step": 1, "description": "<string>", "command_type": "<string from vocabulary>", "target": "<string>", "namespace": "<string>", "command": "<string>", "args": {}, "risk_level": "<low|medium|high|critical>", "impact_summary": "<string>", "timeout_seconds": 60, "wait_after_seconds": 10, "verify_command": "<string>"}],
    "rollback_plan": [{"step": 1, "description": "<string>", "command_type": "<string>", "target": "<string>", "command": "<string>", "risk_level": "<string>", "impact_summary": "<string>", "timeout_seconds": 60, "wait_after_seconds": 10}],
    "estimated_time": "<string>",
    "overall_risk": "<low|medium|high|critical>",
    "preconditions": ["<string>"],
    "warnings": ["<string>"]
  },{{ end }}
  "confidence": 0.85
}
`

// PromptBuilder constructs system and user prompts for the Claude API.
type PromptBuilder struct{}

// Build renders the system prompt and user message for the given analysis request.
func (pb *PromptBuilder) Build(req AnalysisRequest) (string, string, error) {
	var buf bytes.Buffer
	if err := userPromptTemplate.Execute(&buf, req); err != nil {
		return "", "", fmt.Errorf("execute user prompt template: %w", err)
	}
	return systemPrompt, buf.String(), nil
}
