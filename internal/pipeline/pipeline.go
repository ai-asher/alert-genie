package pipeline

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/alert-genie/alert-genie/internal/alert"
	"github.com/alert-genie/alert-genie/internal/analyzer"
	"github.com/alert-genie/alert-genie/internal/approval"
	"github.com/alert-genie/alert-genie/internal/config"
	"github.com/alert-genie/alert-genie/internal/executor"
	"github.com/alert-genie/alert-genie/internal/incidents"
	"github.com/alert-genie/alert-genie/internal/metrics"
	"github.com/alert-genie/alert-genie/internal/notifier"
	"github.com/alert-genie/alert-genie/internal/safety"
	"github.com/alert-genie/alert-genie/internal/store"
	"github.com/alert-genie/alert-genie/internal/topology"
)

// Pipeline orchestrates the alert-to-action flow.
type Pipeline struct {
	cfg       *config.Config
	fetcher   metrics.Fetcher
	analyzer  analyzer.Analyzer
	safety    safety.Validator
	approval  approval.Manager
	router    *executor.Router
	notifier  notifier.Notifier
	store     store.Store
	topology  topology.Provider
	retriever incidents.Retriever
	logger    *slog.Logger
}

// New creates a new Pipeline with all dependencies injected.
// retriever may be nil — in that case historical context enrichment is skipped.
func New(
	cfg *config.Config,
	fetcher metrics.Fetcher,
	az analyzer.Analyzer,
	sv safety.Validator,
	am approval.Manager,
	router *executor.Router,
	n notifier.Notifier,
	st store.Store,
	tp topology.Provider,
	retriever incidents.Retriever,
	logger *slog.Logger,
) *Pipeline {
	return &Pipeline{
		cfg:       cfg,
		fetcher:   fetcher,
		analyzer:  az,
		safety:    sv,
		approval:  am,
		router:    router,
		notifier:  n,
		store:     st,
		topology:  tp,
		retriever: retriever,
		logger:    logger,
	}
}

// ProcessAlert is the main entry point called by the alert handler's ProcessFunc.
// Each alert in the payload is processed asynchronously with its assigned UUID.
func (p *Pipeline) ProcessAlert(ctx context.Context, payload alert.WebhookPayload, persisted []alert.PersistedAlert) {
	for _, pa := range persisted {
		go p.processOne(context.Background(), pa.ID, pa.Alert, payload)
	}
}

func (p *Pipeline) processOne(ctx context.Context, alertID string, a alert.Alert, payload alert.WebhookPayload) {
	alertName := a.AlertName()
	p.logger.Info("pipeline processing alert",
		"alert_id", alertID,
		"alertname", alertName,
		"severity", a.Severity(),
	)

	// 1. Fetch related metrics from Prometheus
	allMetrics := p.fetchMetrics(ctx, a)

	// 2. Load topology
	serviceName := a.Labels["service"]
	if serviceName == "" {
		serviceName = a.Labels["job"]
	}
	topo := p.topology.Get(serviceName)

	// 3. Build analysis request
	var topoCtx *analyzer.TopologyContext
	if topo != nil {
		topoCtx = convertTopology(topo)
	}

	// 3.5. Fetch historical incidents for additional context. This is
	// best-effort — failures degrade gracefully to "no historical context".
	historical := p.fetchHistorical(ctx, alertID, a)

	req := analyzer.AnalysisRequest{
		AlertName:           alertName,
		AlertStatus:         a.Status,
		Severity:            a.Severity(),
		Labels:              a.Labels,
		Annotations:         a.Annotations,
		StartsAt:            a.StartsAt,
		Duration:            time.Since(a.StartsAt),
		GroupKey:            payload.GroupKey,
		TotalInGroup:        len(payload.Alerts),
		CommonLabels:        payload.CommonLabels,
		GeneratorURL:        a.GeneratorURL,
		Metrics:             allMetrics,
		Topology:            topoCtx,
		Mode:                analyzer.Mode(p.cfg.Mode),
		HistoricalIncidents: historical,
	}

	// 4. Call LLM for analysis
	result, err := p.analyzer.Analyze(ctx, req)
	if err != nil {
		p.logger.Error("analysis failed", "alertname", alertName, "error", err)
		// Send a degraded notification
		p.notifier.SendAnalysis(ctx, notifier.AnalysisCard{
			Summary:  fmt.Sprintf("Analysis failed: %v. Alert: %s - %s", err, alertName, a.Annotations["summary"]),
			Severity: a.Severity(),
		})
		return
	}

	// 5. Persist analysis
	analysisJSON, _ := json.Marshal(result)
	p.store.SaveAnalysis(ctx, &store.AnalysisRecord{
		ID:           generateID(),
		AlertID:      alertID,
		Mode:         p.cfg.Mode,
		ResultJSON:   string(analysisJSON),
		ModelUsed:    result.ModelUsed,
		InputTokens:  result.TokensUsed.InputTokens,
		OutputTokens: result.TokensUsed.OutputTokens,
		LatencyMs:    0,
		CreatedAt:    time.Now(),
	})

	// 6. Build notification card from analysis result
	card := buildAnalysisCard(result)

	// 7. Branch: ReadOnly vs Healing
	if p.cfg.Mode == "readonly" || result.HealingPlan == nil {
		msgID, err := p.notifier.SendAnalysis(ctx, card)
		if err != nil {
			p.logger.Error("failed to send analysis", "error", err)
			return
		}
		// Create conversation so users can @Bot to ask follow-up questions
		p.createConversation(ctx, alertID, "", msgID)
		return
	}

	// 8. Healing mode: validate ALL commands through safety system
	plan := result.HealingPlan
	allSafe := true
	for i, cmd := range plan.Commands {
		verdict, err := p.safety.Validate(ctx, safety.Command{
			Raw:         cmd.Command,
			CommandType: cmd.CommandType,
			Target:      cmd.Target,
			Namespace:   cmd.Namespace,
		})
		if err != nil || !verdict.Allowed {
			reason := "unknown"
			if verdict != nil {
				reason = verdict.Reason
			}
			p.logger.Warn("command blocked by safety",
				"step", cmd.Step,
				"command", cmd.Command,
				"reason", reason,
			)
			plan.Commands[i].Description += " [BLOCKED: " + reason + "]"
			allSafe = false
		}
	}

	if !allSafe {
		plan.Warnings = append(plan.Warnings,
			"One or more commands were blocked by the safety system. Review the plan carefully.")
	}

	// 9. Send healing plan card with approve/reject buttons
	healingCard := buildHealingPlanCard(result, card)

	msgID, err := p.notifier.SendHealingPlan(ctx, healingCard)
	if err != nil {
		p.logger.Error("failed to send healing plan", "error", err)
		return
	}

	// 10. Create approval record
	planJSON, _ := json.Marshal(plan)
	approvalID, err := p.approval.CreateApproval(ctx,
		alertID, string(planJSON), msgID, p.cfg.Approval.TTL)
	if err != nil {
		p.logger.Error("failed to create approval", "error", err)
	}

	// 11. Create conversation so users can @Bot to ask follow-ups
	p.createConversation(ctx, alertID, approvalID, msgID)

	p.logger.Info("healing plan sent for approval",
		"alertname", alertName,
		"approval_id", approvalID,
		"commands", len(plan.Commands),
	)
}

// createConversation creates a conversation record bound to the alert and rooted at
// the message ID of the original card. Failures are logged but not fatal.
func (p *Pipeline) createConversation(ctx context.Context, alertID, approvalID, rootMessageID string) {
	if rootMessageID == "" {
		return
	}
	convID, err := generateUUID()
	if err != nil {
		p.logger.Warn("conversation id generation failed", "error", err)
		return
	}
	now := time.Now()
	conv := &store.Conversation{
		ID:            convID,
		AlertID:       alertID,
		ApprovalID:    approvalID,
		LarkChatID:    p.cfg.Lark.AlertChatID,
		RootMessageID: rootMessageID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := p.store.SaveConversation(ctx, conv); err != nil {
		p.logger.Warn("save conversation failed", "error", err)
	}
}

// HandleApprovalCallback processes an approval callback from Lark.
// This is called by the notifier callback handler.
func (p *Pipeline) HandleApprovalCallback(ctx context.Context, approvalID, action, userID string) error {
	if err := p.approval.ProcessCallback(ctx, approvalID, action, userID); err != nil {
		return err
	}

	if action == "approve" {
		// Fetch the approval record and execute the plan
		record, err := p.store.GetApproval(ctx, approvalID)
		if err != nil || record == nil {
			return fmt.Errorf("get approval for execution: %w", err)
		}
		go p.router.ExecutePlan(context.Background(), record)
	}

	return nil
}

// HandleFeedbackCallback persists user feedback (👍 / 👎 / 💬) on a plan
// and updates the alert outcome cache used by historical retrieval.
//
// The "feedback_comment" action only triggers a toast asking the user to
// reply with text in the thread — the actual comment will arrive as a
// chat event (see chat orchestrator) which writes a "comment_only"
// IncidentFeedback row.
func (p *Pipeline) HandleFeedbackCallback(ctx context.Context, alertID, approvalID, action, userID string) error {
	rating := ""
	switch action {
	case "feedback_thumbs_up":
		rating = "thumbs_up"
	case "feedback_thumbs_down":
		rating = "thumbs_down"
	case "feedback_comment":
		// We don't persist a row for "comment" — the actual comment text
		// arrives later via chat events. Just acknowledge.
		return nil
	default:
		return fmt.Errorf("unknown feedback action: %s", action)
	}

	id, err := generateUUID()
	if err != nil {
		return fmt.Errorf("generate feedback id: %w", err)
	}
	fb := &store.IncidentFeedback{
		ID:         id,
		AlertID:    alertID,
		ApprovalID: approvalID,
		Rating:     rating,
		UserOpenID: userID,
		CreatedAt:  time.Now(),
	}
	if err := p.store.SaveFeedback(ctx, fb); err != nil {
		return fmt.Errorf("save feedback: %w", err)
	}

	// Refresh the alert_outcomes summary so the retriever sees this new vote.
	p.refreshOutcome(ctx, alertID)

	p.logger.Info("feedback recorded",
		"alert_id", alertID, "approval_id", approvalID,
		"rating", rating, "user", userID)
	return nil
}

// refreshOutcome aggregates feedback + final approval status into
// alert_outcomes for the given alert. Best-effort; failures are logged.
func (p *Pipeline) refreshOutcome(ctx context.Context, alertID string) {
	feedback, err := p.store.ListFeedback(ctx, alertID)
	if err != nil {
		p.logger.Warn("list feedback failed", "alert_id", alertID, "error", err)
		return
	}

	up, down := 0, 0
	for _, f := range feedback {
		switch f.Rating {
		case "thumbs_up":
			up++
		case "thumbs_down":
			down++
		}
	}
	feedbackSummary := fmt.Sprintf("thumbs_up=%d thumbs_down=%d", up, down)

	// Pull the most recent approval for this alert to use as final status.
	finalStatus := ""
	approvals, _ := p.store.ListApprovals(ctx, store.ApprovalFilter{Limit: 50})
	for _, ap := range approvals {
		if ap.AlertID == alertID {
			finalStatus = ap.Status
			break // approvals are already ordered desc by requested_at
		}
	}

	o := &store.AlertOutcome{
		AlertID:             alertID,
		FinalApprovalStatus: finalStatus,
		FeedbackSummary:     feedbackSummary,
		UpdatedAt:           time.Now(),
	}
	if err := p.store.UpsertOutcome(ctx, o); err != nil {
		p.logger.Warn("upsert outcome failed", "alert_id", alertID, "error", err)
	}
}

// StartExpireLoop starts a background goroutine that periodically expires stale approvals
// and purges old processed_events idempotency records.
func (p *Pipeline) StartExpireLoop(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.Approval.ExpireCheckInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				expired, err := p.approval.ExpireStale(ctx)
				if err != nil {
					p.logger.Error("expire stale approvals failed", "error", err)
				} else if expired > 0 {
					p.logger.Info("expired stale approvals", "count", expired)
				}

				// Purge processed_events older than 24h. Lark won't retry an event
				// that long after delivery, so this window is more than enough.
				purged, err := p.store.PurgeOldEvents(ctx, time.Now().Add(-24*time.Hour))
				if err != nil {
					p.logger.Error("purge old events failed", "error", err)
				} else if purged > 0 {
					p.logger.Debug("purged old events", "count", purged)
				}
			}
		}
	}()
}

// fetchMetrics queries Prometheus for metrics related to the alert.
// fetchHistorical retrieves and converts historical incidents for the alert.
// Best-effort: returns nil on any error so the analyzer call still proceeds.
func (p *Pipeline) fetchHistorical(ctx context.Context, alertID string, a alert.Alert) []analyzer.HistoricalIncident {
	if p.retriever == nil {
		return nil
	}
	current := incidents.CurrentAlert{
		AlertID:     alertID,
		AlertName:   a.AlertName(),
		Severity:    a.Severity(),
		Labels:      a.Labels,
		Annotations: a.Annotations,
	}
	hist, err := p.retriever.Retrieve(ctx, current)
	if err != nil {
		p.logger.Warn("historical retrieval failed, continuing without it",
			"alertname", a.AlertName(), "error", err)
		return nil
	}
	if len(hist) == 0 {
		return nil
	}
	out := make([]analyzer.HistoricalIncident, 0, len(hist))
	for _, h := range hist {
		out = append(out, analyzer.HistoricalIncident{
			AlertID:         h.AlertID,
			AlertName:       h.AlertName,
			Severity:        h.Severity,
			StartedAt:       h.StartedAt,
			Labels:          h.Labels,
			AnalysisSummary: h.AnalysisSummary,
			RootCause:       h.RootCause,
			HealingSummary:  h.HealingSummary,
			FinalStatus:     h.FinalStatus,
			FeedbackSummary: h.FeedbackSummary,
			ResolvedVia:     h.ResolvedVia,
			RelevanceReason: h.RelevanceReason,
		})
	}
	p.logger.Info("historical incidents retrieved",
		"alertname", a.AlertName(), "count", len(out))
	return out
}

func (p *Pipeline) fetchMetrics(ctx context.Context, a alert.Alert) []metrics.MetricSeries {
	alertName := a.AlertName()
	queries, ok := p.cfg.Prometheus.AlertQueries[alertName]
	if !ok {
		p.logger.Debug("no configured queries for alert", "alertname", alertName)
		return nil
	}

	var allMetrics []metrics.MetricSeries
	for _, queryTmpl := range queries {
		query := expandQueryTemplate(queryTmpl, a.Labels)
		series, err := p.fetcher.QueryRange(ctx, query, time.Now(), p.cfg.Prometheus.QueryWindow)
		if err != nil {
			p.logger.Warn("metric query failed", "query", query, "error", err)
			continue
		}
		allMetrics = append(allMetrics, series...)
	}
	return allMetrics
}

// expandQueryTemplate replaces {{.label}} placeholders with actual label values.
func expandQueryTemplate(tmpl string, labels map[string]string) string {
	result := tmpl
	for k, v := range labels {
		result = strings.ReplaceAll(result, "{{."+k+"}}", v)
	}
	return result
}

// convertTopology converts a topology.ServiceTopology to analyzer.TopologyContext.
func convertTopology(t *topology.ServiceTopology) *analyzer.TopologyContext {
	ctx := &analyzer.TopologyContext{
		ServiceName: t.ServiceName,
		OwnerTeam:   t.OwnerTeam,
		Tier:        t.Tier,
	}
	for _, d := range t.Dependencies {
		ctx.Dependencies = append(ctx.Dependencies, analyzer.TopologyEntry{
			Name:        d.Name,
			Type:        d.Type,
			Description: d.Description,
		})
	}
	for _, d := range t.Downstream {
		ctx.Downstream = append(ctx.Downstream, analyzer.TopologyEntry{
			Name:                d.Name,
			ImpactIfUnavailable: d.ImpactIfUnavailable,
		})
	}
	for _, f := range t.KnownFailureModes {
		ctx.KnownFailureModes = append(ctx.KnownFailureModes, analyzer.FailureMode{
			Mode:              f.Mode,
			TypicalCause:      f.TypicalCause,
			TypicalResolution: f.TypicalResolution,
		})
	}
	return ctx
}

// buildAnalysisCard converts an AnalysisResult to a notifier.AnalysisCard.
func buildAnalysisCard(r *analyzer.AnalysisResult) notifier.AnalysisCard {
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

// buildHealingPlanCard converts analysis result to a notifier.HealingPlanCard.
func buildHealingPlanCard(r *analyzer.AnalysisResult, card notifier.AnalysisCard) notifier.HealingPlanCard {
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

func generateID() string {
	id, _ := generateUUID()
	return id
}

func generateUUID() (string, error) {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		return "", err
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16]), nil
}
