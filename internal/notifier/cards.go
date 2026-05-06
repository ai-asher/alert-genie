package notifier

import (
	"fmt"
	"strings"
)

// severityToColor maps alert severity to Lark card header color.
func severityToColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "error":
		return "red"
	case "warning":
		return "orange"
	case "info":
		return "blue"
	default:
		return "blue"
	}
}

// riskBadge returns a formatted risk badge string.
func riskBadge(risk string) string {
	switch strings.ToLower(risk) {
	case "low":
		return "🟢 Low"
	case "medium":
		return "🟡 Medium"
	case "high":
		return "🟠 High"
	case "critical":
		return "🔴 Critical"
	default:
		return "⚪ " + risk
	}
}

// buildAnalysisCard constructs a Lark interactive card JSON for an analysis result.
func buildAnalysisCard(card AnalysisCard) map[string]any {
	elements := []map[string]any{}

	// Summary section
	elements = append(elements, markdownElement(fmt.Sprintf("**Summary**\n%s", card.Summary)))
	elements = append(elements, divider())

	// Root Cause section
	elements = append(elements, markdownElement(fmt.Sprintf("**Root Cause**\n%s", card.RootCause)))
	elements = append(elements, divider())

	// Impact section
	elements = append(elements, markdownElement(fmt.Sprintf("**Impact**\n%s", card.Impact)))
	elements = append(elements, divider())

	// Metric Insights section
	if len(card.MetricInsights) > 0 {
		var lines []string
		lines = append(lines, "**Metric Insights**")
		for _, m := range card.MetricInsights {
			lines = append(lines, fmt.Sprintf("- **%s** (%s): %s", m.MetricName, m.Trend, m.Observation))
		}
		elements = append(elements, markdownElement(strings.Join(lines, "\n")))
		elements = append(elements, divider())
	}

	// Affected Services section
	if len(card.AffectedServices) > 0 {
		elements = append(elements, markdownElement(
			fmt.Sprintf("**Affected Services**\n%s", strings.Join(card.AffectedServices, ", ")),
		))
		elements = append(elements, divider())
	}

	// Recommendations section
	if len(card.Recommendations) > 0 {
		var lines []string
		lines = append(lines, "**Recommendations**")
		for i, r := range card.Recommendations {
			lines = append(lines, fmt.Sprintf("%d. %s", i+1, r))
		}
		elements = append(elements, markdownElement(strings.Join(lines, "\n")))
		elements = append(elements, divider())
	}

	// Correlated dependent alerts section.
	if section := buildDependentsSection(card.Dependents); section != "" {
		elements = append(elements, markdownElement(section))
		elements = append(elements, divider())
	}

	// Footer: confidence, timestamp, model info
	footerParts := []string{
		fmt.Sprintf("Confidence: **%.0f%%**", card.Confidence*100),
		fmt.Sprintf("Model: %s", card.ModelUsed),
		fmt.Sprintf("Tokens: %d in / %d out", card.InputTokens, card.OutputTokens),
	}
	if card.AnalyzedAt != "" {
		footerParts = append(footerParts, fmt.Sprintf("Analyzed at: %s", card.AnalyzedAt))
	}
	elements = append(elements, markdownElement(strings.Join(footerParts, " | ")))

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": fmt.Sprintf("[%s] Alert Analysis", strings.ToUpper(card.Severity)),
			},
			"template": severityToColor(card.Severity),
		},
		"elements": elements,
	}
}

// buildHealingPlanCard constructs a Lark interactive card JSON for a healing plan.
func buildHealingPlanCard(card HealingPlanCard) map[string]any {
	elements := []map[string]any{}

	// Condensed analysis summary
	elements = append(elements, markdownElement(
		fmt.Sprintf("**Summary:** %s\n**Root Cause:** %s\n**Impact:** %s",
			card.Summary, card.RootCause, card.Impact),
	))
	elements = append(elements, divider())

	// Plan description
	elements = append(elements, markdownElement(
		fmt.Sprintf("**Healing Plan**\n%s", card.PlanDescription),
	))
	elements = append(elements, divider())

	// Command steps
	if len(card.Commands) > 0 {
		var lines []string
		lines = append(lines, "**Command Steps**")
		for _, c := range card.Commands {
			lines = append(lines, fmt.Sprintf(
				"%d. %s [%s]\n   `%s` → %s (timeout: %ds, risk: %s)",
				c.Step, c.Description, c.CommandType, c.Command, c.Target, c.TimeoutSec, riskBadge(c.RiskLevel),
			))
			if impact := renderBlastRadius(c.BlastRadius); impact != "" {
				lines = append(lines, impact)
			}
		}
		elements = append(elements, markdownElement(strings.Join(lines, "\n")))
		elements = append(elements, divider())
	}

	// Warnings
	if len(card.Warnings) > 0 {
		var lines []string
		lines = append(lines, "**⚠️ Warnings**")
		for _, w := range card.Warnings {
			lines = append(lines, fmt.Sprintf("- %s", w))
		}
		elements = append(elements, markdownElement(strings.Join(lines, "\n")))
		elements = append(elements, divider())
	}

	// Correlated dependent alerts section.
	if section := buildDependentsSection(card.Dependents); section != "" {
		elements = append(elements, markdownElement(section))
		elements = append(elements, divider())
	}

	// Rollback and risk info
	elements = append(elements, markdownElement(
		fmt.Sprintf("Overall Risk: %s | Rollback Steps: %d | Estimated Time: %s",
			riskBadge(card.OverallRisk), card.RollbackSteps, card.EstimatedTime),
	))
	elements = append(elements, divider())

	// Action buttons: Approve / Reject / Modify & Approve
	elements = append(elements, map[string]any{
		"tag": "action",
		"actions": []map[string]any{
			{
				"tag": "button",
				"text": map[string]any{
					"tag":     "plain_text",
					"content": "✅ Approve",
				},
				"type": "primary",
				"value": map[string]any{
					"action":      "approve",
					"approval_id": card.ApprovalID,
				},
			},
			{
				"tag": "button",
				"text": map[string]any{
					"tag":     "plain_text",
					"content": "❌ Reject",
				},
				"type": "danger",
				"value": map[string]any{
					"action":      "reject",
					"approval_id": card.ApprovalID,
				},
			},
			{
				"tag": "button",
				"text": map[string]any{
					"tag":     "plain_text",
					"content": "✏️ Modify & Approve",
				},
				"type": "default",
				"value": map[string]any{
					"action":      "modify",
					"approval_id": card.ApprovalID,
				},
			},
		},
	})

	// Footer
	footerParts := []string{
		fmt.Sprintf("Confidence: **%.0f%%**", card.Confidence*100),
		fmt.Sprintf("Model: %s", card.ModelUsed),
	}
	if card.AnalyzedAt != "" {
		footerParts = append(footerParts, fmt.Sprintf("Analyzed at: %s", card.AnalyzedAt))
	}
	elements = append(elements, markdownElement(strings.Join(footerParts, " | ")))

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": fmt.Sprintf("[%s] Healing Plan - Approval Required", strings.ToUpper(card.Severity)),
			},
			"template": severityToColor(card.Severity),
		},
		"elements": elements,
	}
}

// buildProgressCard constructs a Lark interactive card JSON for execution progress.
func buildProgressCard(progress ExecutionProgress) map[string]any {
	elements := []map[string]any{}

	var lines []string
	lines = append(lines, "**Execution Progress**")
	for _, s := range progress.Steps {
		icon := statusIcon(s.Status)
		line := fmt.Sprintf("%s Step %d: `%s` — %s", icon, s.Step, s.Command, s.Status)
		if s.Error != "" {
			line += fmt.Sprintf("\n   Error: %s", s.Error)
		}
		lines = append(lines, line)
	}
	elements = append(elements, markdownElement(strings.Join(lines, "\n")))

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": "Healing Execution Progress",
			},
			"template": "blue",
		},
		"elements": elements,
	}
}

// buildCompletionCard constructs a Lark interactive card JSON for execution completion.
func buildCompletionCard(success bool, summary string) map[string]any {
	color := "green"
	title := "✅ Execution Completed Successfully"
	if !success {
		color = "red"
		title = "❌ Execution Failed"
	}

	elements := []map[string]any{
		markdownElement(summary),
	}

	return map[string]any{
		"config": map[string]any{
			"wide_screen_mode": true,
		},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": title,
			},
			"template": color,
		},
		"elements": elements,
	}
}

// statusIcon returns a status emoji for execution step display.
func statusIcon(status string) string {
	switch status {
	case "pending":
		return "⏳"
	case "running":
		return "🔄"
	case "success":
		return "✅"
	case "failed":
		return "❌"
	case "skipped":
		return "⏭️"
	default:
		return "❓"
	}
}

// buildFeedbackCard renders a 👍 / 👎 / 💬 feedback card following plan
// execution. Button values carry alert_id and approval_id so the callback
// handler can write IncidentFeedback rows. Comment button opens a short
// input dialog (Lark's input element) so users can type a free-text note.
func buildFeedbackCard(c FeedbackCard) map[string]any {
	color := "blue"
	headline := "How did this plan land?"
	switch c.OutcomeStatus {
	case "success":
		color = "green"
		headline = "✅ Plan executed — did it actually fix the issue?"
	case "failed":
		color = "red"
		headline = "❌ Plan execution failed — was the diagnosis right?"
	case "manual_resolution":
		color = "blue"
		headline = "ℹ️ Issue resolved without auto-healing — was the analysis useful?"
	}

	intro := "Quick feedback helps Alert-Genie learn. Future similar alerts will reference this."
	if c.Note != "" {
		intro = c.Note + "\n\n" + intro
	}

	elements := []map[string]any{
		markdownElement(fmt.Sprintf("**Alert:** %s", c.AlertName)),
		markdownElement(intro),
		divider(),
		{
			"tag": "action",
			"actions": []map[string]any{
				{
					"tag":  "button",
					"text": map[string]any{"tag": "plain_text", "content": "👍 Worked"},
					"type": "primary",
					"value": map[string]string{
						"action":      "feedback_thumbs_up",
						"alert_id":    c.AlertID,
						"approval_id": c.ApprovalID,
					},
				},
				{
					"tag":  "button",
					"text": map[string]any{"tag": "plain_text", "content": "👎 Didn't work"},
					"type": "danger",
					"value": map[string]string{
						"action":      "feedback_thumbs_down",
						"alert_id":    c.AlertID,
						"approval_id": c.ApprovalID,
					},
				},
				{
					"tag":  "button",
					"text": map[string]any{"tag": "plain_text", "content": "💬 Comment"},
					"type": "default",
					"value": map[string]string{
						"action":      "feedback_comment",
						"alert_id":    c.AlertID,
						"approval_id": c.ApprovalID,
					},
				},
			},
		},
	}

	return map[string]any{
		"config": map[string]any{"wide_screen_mode": true},
		"header": map[string]any{
			"title": map[string]any{
				"tag":     "plain_text",
				"content": headline,
			},
			"template": color,
		},
		"elements": elements,
	}
}

// buildDependentsSection renders the collapsed list of correlated dependent
// alerts shown on analysis and healing-plan cards. Returns "" when there are
// no dependents so callers can skip emitting an empty element.
//
// The list is truncated to maxDependentsShown entries; if there are more, an
// overflow note ("…and N more") is appended so users know the full count
// without flooding the card.
func buildDependentsSection(deps []DependentAlertSummary) string {
	const maxDependentsShown = 5
	if len(deps) == 0 {
		return ""
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("### 🔗 %d other alert(s) correlated with this one", len(deps)))
	limit := len(deps)
	if limit > maxDependentsShown {
		limit = maxDependentsShown
	}
	for i := 0; i < limit; i++ {
		d := deps[i]
		loc := ""
		if d.Service != "" && d.Namespace != "" {
			loc = fmt.Sprintf(" on %s/%s", d.Service, d.Namespace)
		} else if d.Service != "" {
			loc = " on " + d.Service
		} else if d.Namespace != "" {
			loc = " in " + d.Namespace
		}
		lines = append(lines, fmt.Sprintf("- **%s** (%s)%s", d.AlertName, d.Severity, loc))
	}
	if len(deps) > maxDependentsShown {
		lines = append(lines, fmt.Sprintf("- …and %d more", len(deps)-maxDependentsShown))
	}
	return strings.Join(lines, "\n")
}

// renderBlastRadius produces the per-command "📊 Impact:" markdown block for
// the healing plan card. Returns an empty string when br is nil so callers
// can simply concatenate without extra branches.
//
// The block format is:
//
//	📊 Impact: <severity>, ~<X>% traffic, <N> replicas, <D> dependents
//	- finding 1
//	- finding 2
//	⚠️ Risk upgraded: low → high (reason: ...)
//
// Only the top two findings are rendered to keep the card compact; the rest
// are summarized as "(+N more)".
func renderBlastRadius(br *CommandBlastRadius) string {
	if br == nil {
		return ""
	}
	var b strings.Builder
	// Headline summary line.
	b.WriteString("   📊 Impact: ")
	parts := []string{riskBadge(br.Severity)}
	if br.EstimatedTrafficPct > 0 {
		parts = append(parts, fmt.Sprintf("~%.1f%% traffic", br.EstimatedTrafficPct))
	}
	if br.EstimatedReplicas > 0 {
		parts = append(parts, fmt.Sprintf("%d replica(s)", br.EstimatedReplicas))
	}
	if br.DependentServiceCount > 0 {
		parts = append(parts, fmt.Sprintf("%d dependent(s)", br.DependentServiceCount))
	}
	b.WriteString(strings.Join(parts, " | "))

	// Top two findings as bullets; squash the rest into a counter.
	if len(br.Findings) > 0 {
		max := 2
		if len(br.Findings) < max {
			max = len(br.Findings)
		}
		for i := 0; i < max; i++ {
			b.WriteString("\n   - ")
			b.WriteString(br.Findings[i])
		}
		if len(br.Findings) > max {
			b.WriteString(fmt.Sprintf("\n   - (+%d more finding(s))", len(br.Findings)-max))
		}
	} else {
		b.WriteString("\n   - insufficient data")
	}

	if br.UpgradedFromLLM != "" {
		b.WriteString("\n   ⚠️ Risk upgraded: ")
		b.WriteString(br.UpgradedFromLLM)
	}
	return b.String()
}

// markdownElement creates a Lark card markdown element.
func markdownElement(content string) map[string]any {
	return map[string]any{
		"tag": "div",
		"text": map[string]any{
			"tag":     "lark_md",
			"content": content,
		},
	}
}

// divider creates a Lark card divider element.
func divider() map[string]any {
	return map[string]any{
		"tag": "hr",
	}
}
