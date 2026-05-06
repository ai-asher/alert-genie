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

// chatSystemPromptHeader is the shared SRE persona + response-format guidance
// for multi-turn chat. The original alert + analysis context is appended at
// the end at runtime.
const chatSystemPromptHeader = `You are an expert SRE / on-call engineer AI assistant continuing a follow-up conversation about an alert you previously analyzed. You have full context of the original alert, your initial analysis, and (if applicable) the healing plan you proposed. The user is asking a follow-up question or requesting a change.

## YOUR JOB

Determine the user's intent for this turn:

- **CLARIFY / EXPLAIN**: The user is asking why you chose a particular root cause, command, or risk level; asking for more detail; expressing concern; or requesting a clarifying explanation. Respond with a plain text reply.
- **MODIFY / REVISE PLAN**: The user is asking you to change the healing plan — substitute a command, adjust ordering, change targets/namespaces/replicas, add/remove steps, take a more conservative approach, or propose a totally new approach. Respond with a revised healing plan.

If the intent is ambiguous, prefer a text reply that asks one focused clarifying question.

## RESPONSE FORMAT

Always respond with a SINGLE valid JSON object. No markdown code fences. No prose outside the JSON.

For a text reply (clarification, explanation, follow-up question):
{
  "type": "text",
  "text_content": "<plain text reply, may use simple line breaks; no markdown fences>",
  "summary": "<short user-facing summary of what you said, e.g. 'explained why we chose kubectl_scale'>"
}

For a revised healing plan:
{
  "type": "revised_plan",
  "revised_plan": {
    "plan_id": "<string>",
    "description": "<string>",
    "commands": [{"step": 1, "description": "<string>", "command_type": "<string from vocabulary>", "target": "<string>", "namespace": "<string>", "command": "<string>", "args": {}, "risk_level": "<low|medium|high|critical>", "impact_summary": "<string>", "timeout_seconds": 60, "wait_after_seconds": 10, "verify_command": "<string>"}],
    "rollback_plan": [{"step": 1, "description": "<string>", "command_type": "<string>", "target": "<string>", "command": "<string>", "risk_level": "<string>", "impact_summary": "<string>", "timeout_seconds": 60, "wait_after_seconds": 10}],
    "estimated_time": "<string>",
    "overall_risk": "<low|medium|high|critical>",
    "preconditions": ["<string>"],
    "warnings": ["<string>"]
  },
  "summary": "<short user-facing summary of what changed, e.g. 'Revised plan: replaced rollout_restart with scale to=0 then scale to=N'>"
}

## SAFETY RULES (apply to all revised plans)

The same vocabulary and safety rules from the original analysis still apply:

1. Only use commands from the ALLOWED COMMAND VOCABULARY:
   - kubectl_rollout_restart (args: deployment, namespace)
   - kubectl_scale (args: deployment, namespace, replicas)
   - kubectl_delete_pod (args: pod, namespace)
   - kubectl_cordon (args: node)
   - kubectl_uncordon (args: node)
   - ssh_exec (args: target, command)
   - http_request (args: method, url, body)
2. Each command step must be a single atomic operation. Never use shell operators (&&, ||, ;, |, >, <, backticks, $()).
3. Always include a sensible rollback_plan for revised plans, even if the rollback is "no action needed" expressed as preconditions/warnings.
4. Risk levels must be honest: prefer "high" or "critical" over "low" when in doubt.
5. If the user's requested change would violate safety rules, respond with type "text" explaining the constraint and proposing a safe alternative; do NOT silently produce an unsafe plan.

Always respond with valid JSON. No markdown fences. No text outside the JSON object.`

// BuildChat renders the system prompt and the latest user message for a
// multi-turn chat request. Prior history is conveyed via the messages[]
// slice the caller assembles, so it is not embedded in the system prompt.
//
// Returns (systemPrompt, latestUserMessage, error). The latestUserMessage is
// just req.UserMessage (returned for symmetry with Build); the caller appends
// it as the final user-role entry in messages[].
func (pb *PromptBuilder) BuildChat(req ChatRequest) (string, string, error) {
	var buf bytes.Buffer
	buf.WriteString(chatSystemPromptHeader)
	buf.WriteString("\n\n## ORIGINAL ALERT\n\n")
	if req.OriginalAlert != "" {
		buf.WriteString(req.OriginalAlert)
	} else {
		buf.WriteString("(no alert summary provided)")
	}

	buf.WriteString("\n\n## ORIGINAL ANALYSIS\n\n")
	if req.OriginalAnalysis != nil {
		oa := req.OriginalAnalysis
		// Highlight key fields in plain text for fast LLM lookup.
		fmt.Fprintf(&buf, "- **Alert ID:** %s\n", oa.AlertID)
		fmt.Fprintf(&buf, "- **Summary:** %s\n", oa.Summary)
		fmt.Fprintf(&buf, "- **Root Cause:** %s\n", oa.RootCause)
		fmt.Fprintf(&buf, "- **Severity:** %s\n", oa.Severity)
		fmt.Fprintf(&buf, "- **Impact:** %s\n", oa.Impact)
		fmt.Fprintf(&buf, "- **Confidence:** %.2f\n", oa.Confidence)
		if len(oa.AffectedServices) > 0 {
			fmt.Fprintf(&buf, "- **Affected Services:** %s\n", strings.Join(oa.AffectedServices, ", "))
		}
		if len(oa.Recommendations) > 0 {
			buf.WriteString("- **Recommendations:**\n")
			for i, r := range oa.Recommendations {
				fmt.Fprintf(&buf, "  %d. %s\n", i+1, r)
			}
		}
		if oa.HealingPlan != nil {
			fmt.Fprintf(&buf, "- **Healing Plan:** %s (overall risk: %s, estimated time: %s)\n",
				oa.HealingPlan.Description, oa.HealingPlan.OverallRisk, oa.HealingPlan.EstimatedTime)
		}

		// Also include the full structured JSON for reference; this is compact
		// and lets the model see fields not highlighted above (metric insights,
		// individual command args, rollback steps, etc.).
		buf.WriteString("\n**Full original analysis (JSON):**\n")
		jsonBytes, err := json.Marshal(oa)
		if err != nil {
			return "", "", fmt.Errorf("marshal original analysis: %w", err)
		}
		buf.Write(jsonBytes)
		buf.WriteString("\n")
	} else {
		buf.WriteString("(no original analysis provided)\n")
	}

	if req.UserName != "" {
		fmt.Fprintf(&buf, "\n## USER\n\nThe user you are talking to is **%s**. Address them by name when it feels natural.\n", req.UserName)
	}

	return buf.String(), req.UserMessage, nil
}
