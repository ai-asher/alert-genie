package chat

import (
	"github.com/alert-genie/alert-genie/internal/analyzer"
	"github.com/alert-genie/alert-genie/internal/notifier"
)

// buildAnalysisCardFromResult mirrors pipeline.buildAnalysisCard.
// Duplicated here to avoid an import cycle (pipeline imports chat).
func buildAnalysisCardFromResult(r *analyzer.AnalysisResult) notifier.AnalysisCard {
	insights := make([]notifier.MetricInsightCard, len(r.MetricInsights))
	for i, m := range r.MetricInsights {
		insights[i] = notifier.MetricInsightCard{
			MetricName:  m.MetricName,
			Trend:       m.Trend,
			Observation: m.Observation,
		}
	}
	return notifier.AnalysisCard{
		Summary:          r.Summary,
		RootCause:        r.RootCause,
		Severity:         r.Severity,
		Impact:           r.Impact,
		AffectedServices: r.AffectedServices,
		MetricInsights:   insights,
		Recommendations:  r.Recommendations,
		Confidence:       r.Confidence,
		AnalyzedAt:       r.AnalyzedAt.Format("2006-01-02 15:04:05"),
		ModelUsed:        r.ModelUsed,
		InputTokens:      r.TokensUsed.InputTokens,
		OutputTokens:     r.TokensUsed.OutputTokens,
	}
}

// buildHealingPlanCardFromResult mirrors pipeline.buildHealingPlanCard.
func buildHealingPlanCardFromResult(r *analyzer.AnalysisResult, card notifier.AnalysisCard) notifier.HealingPlanCard {
	plan := r.HealingPlan
	cmds := make([]notifier.CommandCard, len(plan.Commands))
	for i, c := range plan.Commands {
		cmds[i] = notifier.CommandCard{
			Step:        c.Step,
			Description: c.Description,
			CommandType: c.CommandType,
			Command:     c.Command,
			Target:      c.Target,
			RiskLevel:   c.RiskLevel,
			TimeoutSec:  c.TimeoutSec,
		}
	}
	return notifier.HealingPlanCard{
		AnalysisCard:    card,
		PlanDescription: plan.Description,
		Commands:        cmds,
		RollbackSteps:   len(plan.RollbackPlan),
		OverallRisk:     plan.OverallRisk,
		EstimatedTime:   plan.EstimatedTime,
		Warnings:        plan.Warnings,
	}
}
