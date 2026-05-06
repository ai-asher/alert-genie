package blastradius

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alert-genie/alert-genie/internal/metrics"
	"github.com/alert-genie/alert-genie/internal/topology"
)

// Assessor evaluates the blast radius of a single healing command.
type Assessor interface {
	// Assess returns a populated Assessment for the supplied command. It is
	// soft-failing: query errors degrade confidence and add "no_data"
	// findings rather than aborting. The returned error is non-nil only on
	// programmer errors (e.g. nil command); regular network/Prometheus
	// failures do not surface here.
	Assess(ctx context.Context, cmd Command) (*Assessment, error)
}

// Config tunes the assessor's behavior and risk-upgrade thresholds.
type Config struct {
	// Enabled gates the assessor at construction time. When false, callers
	// should pass a nil Assessor instead.
	Enabled bool
	// PrometheusQueryTimeout caps each individual Prometheus query. Defaults
	// to 5s when zero.
	PrometheusQueryTimeout time.Duration
	// HighTrafficThreshold is the fraction (0.0-1.0) of service traffic
	// affected at or above which the computed severity rises to "high".
	// Defaults to 0.5.
	HighTrafficThreshold float64
	// CriticalTrafficThreshold is the fraction (0.0-1.0) of service traffic
	// affected at or above which the computed severity rises to "critical".
	// Defaults to 0.8.
	CriticalTrafficThreshold float64
}

// assessor is the concrete Assessor implementation.
type assessor struct {
	fetcher  metrics.Fetcher
	topology topology.Provider // optional; nil is allowed
	cfg      Config
	logger   *slog.Logger
}

// New constructs a new Assessor. The topology provider is optional and may be
// nil; the fetcher is required (a nil fetcher will produce all-no-data
// assessments). The logger is required.
func New(fetcher metrics.Fetcher, topo topology.Provider, cfg Config, logger *slog.Logger) Assessor {
	if cfg.PrometheusQueryTimeout <= 0 {
		cfg.PrometheusQueryTimeout = 5 * time.Second
	}
	if cfg.HighTrafficThreshold <= 0 {
		cfg.HighTrafficThreshold = 0.5
	}
	if cfg.CriticalTrafficThreshold <= 0 {
		cfg.CriticalTrafficThreshold = 0.8
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &assessor{
		fetcher:  fetcher,
		topology: topo,
		cfg:      cfg,
		logger:   logger,
	}
}

// Compiled regexes for command shape matching. Each captures the resource
// kind, name, and (where applicable) namespace and replica count.
var (
	// kubectl rollout restart deployment/X -n Y    OR    deployment X -n Y
	rolloutRestartRe = regexp.MustCompile(
		`^kubectl\s+rollout\s+restart\s+(deployment|daemonset|statefulset)[/\s]+(\S+)(?:\s+-n\s+(\S+)|\s+--namespace[=\s]+(\S+))?`,
	)
	// kubectl scale deployment/X --replicas=N -n Y
	scaleRe = regexp.MustCompile(
		`^kubectl\s+scale\s+(deployment|statefulset|replicaset)[/\s]+(\S+).*--replicas=(\d+)(?:.*\s+-n\s+(\S+)|.*--namespace[=\s]+(\S+))?`,
	)
	// kubectl rollout undo deployment/X -n Y
	rolloutUndoRe = regexp.MustCompile(
		`^kubectl\s+rollout\s+undo\s+(deployment|daemonset|statefulset)[/\s]+(\S+)(?:\s+-n\s+(\S+)|\s+--namespace[=\s]+(\S+))?`,
	)
	// kubectl delete pod/X -n Y     OR    pod X -n Y
	deletePodRe = regexp.MustCompile(
		`^kubectl\s+delete\s+pod[/\s]+(\S+)(?:\s+-n\s+(\S+)|\s+--namespace[=\s]+(\S+))?`,
	)
	// kubectl patch hpa/X ...       OR    configmap/X ...
	patchRe = regexp.MustCompile(
		`^kubectl\s+patch\s+(hpa|horizontalpodautoscaler|configmap|cm)[/\s]+(\S+)(?:\s+-n\s+(\S+)|\s+--namespace[=\s]+(\S+))?`,
	)
	// systemctl restart <service>
	systemctlRestartRe = regexp.MustCompile(`^systemctl\s+restart\s+(\S+)`)
	// systemctl stop <service>
	systemctlStopRe = regexp.MustCompile(`^systemctl\s+stop\s+(\S+)`)
	// disk cleanup commands
	findDeleteRe = regexp.MustCompile(`^find\s+\S+.*-delete\s*$`)
	rmLogRe      = regexp.MustCompile(`^rm\s+(?:-f\s+)?\S+\.(log|tmp|old|bak)\s*$`)
)

// Assess dispatches to the per-pattern handler that matches the command,
// falling back to a low-confidence "medium" assessment for anything we don't
// recognize.
func (a *assessor) Assess(ctx context.Context, cmd Command) (*Assessment, error) {
	raw := strings.TrimSpace(cmd.Command)
	a.logger.Debug("assessing blast radius",
		slog.String("command_id", cmd.ID),
		slog.String("command", raw),
		slog.String("type", cmd.CommandType),
	)

	var assessment *Assessment
	switch {
	case rolloutRestartRe.MatchString(raw):
		assessment = a.assessRolloutRestart(ctx, cmd, raw)
	case scaleRe.MatchString(raw):
		assessment = a.assessScale(ctx, cmd, raw)
	case rolloutUndoRe.MatchString(raw):
		assessment = a.assessRolloutUndo(ctx, cmd, raw)
	case deletePodRe.MatchString(raw):
		assessment = a.assessDeletePod(ctx, cmd, raw)
	case patchRe.MatchString(raw):
		assessment = a.assessPatch(ctx, cmd, raw)
	case systemctlStopRe.MatchString(raw):
		assessment = a.assessSystemctlStop(ctx, cmd, raw)
	case systemctlRestartRe.MatchString(raw):
		assessment = a.assessSystemctlRestart(ctx, cmd, raw)
	case findDeleteRe.MatchString(raw), rmLogRe.MatchString(raw):
		assessment = a.assessDiskCleanup(ctx, cmd, raw)
	default:
		assessment = a.assessUnknown(cmd)
	}

	a.applyRiskUpgrade(cmd, assessment)
	a.normalize(assessment)
	return assessment, nil
}

// applyRiskUpgrade compares computed severity to the LLM's risk level and
// sets SuggestedRiskUpgrade when computed > LLM.
func (a *assessor) applyRiskUpgrade(cmd Command, assessment *Assessment) {
	if assessment == nil {
		return
	}
	llm := strings.ToLower(strings.TrimSpace(cmd.LLMRiskLevel))
	if severityRank(assessment.OverallSeverity) > severityRank(llm) && llm != "" {
		assessment.SuggestedRiskUpgrade = assessment.OverallSeverity
	}
}

// normalize ensures Assessment fields are within sensible bounds and applies
// the "insufficient data" fallback when we collected no findings at all.
func (a *assessor) normalize(assessment *Assessment) {
	if assessment == nil {
		return
	}
	if assessment.OverallSeverity == "" {
		assessment.OverallSeverity = SeverityMedium
	}
	if assessment.Confidence < 0 {
		assessment.Confidence = 0
	}
	if assessment.Confidence > 1 {
		assessment.Confidence = 1
	}
	if assessment.EstimatedTrafficShareBps < 0 {
		assessment.EstimatedTrafficShareBps = 0
	}
	if assessment.EstimatedTrafficShareBps > 1 {
		assessment.EstimatedTrafficShareBps = 1
	}
	// When the assessor returned absolutely nothing usable, surface a clear
	// "insufficient data" finding so the card renders something rather than
	// disappearing the section entirely.
	if len(assessment.Findings) == 0 {
		assessment.Confidence = 0.2
		assessment.OverallSeverity = SeverityMedium
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingNoData,
			Message: "insufficient data to compute blast radius",
		})
	}
}

// ----------------------------------------------------------------------------
// Per-pattern assessors
// ----------------------------------------------------------------------------

// assessRolloutRestart handles `kubectl rollout restart deployment/X -n Y`.
// It pulls current replica count and traffic share, then estimates downtime
// risk based on the replica count (1 replica is a full outage, 5+ rolls).
func (a *assessor) assessRolloutRestart(ctx context.Context, cmd Command, raw string) *Assessment {
	m := rolloutRestartRe.FindStringSubmatch(raw)
	kind, name, ns := m[1], m[2], pickNamespace(m[3], m[4], cmd.Namespace)

	assessment := &Assessment{
		CommandID:  cmd.ID,
		Confidence: 0.8,
	}

	replicas := a.queryDeploymentReplicas(ctx, kind, name, ns, assessment)
	if replicas > 0 {
		assessment.EstimatedReplicasAffected = replicas
		switch {
		case replicas == 1:
			assessment.Findings = append(assessment.Findings, Finding{
				Kind:    FindingReplicas,
				Message: fmt.Sprintf("%s/%s has only 1 replica; restart causes a full outage during the rollout", kind, name),
			})
		case replicas <= 2:
			assessment.Findings = append(assessment.Findings, Finding{
				Kind:    FindingReplicas,
				Message: fmt.Sprintf("%s/%s has %d replicas; capacity halves briefly during the rolling restart", kind, name, replicas),
			})
		default:
			assessment.Findings = append(assessment.Findings, Finding{
				Kind:    FindingReplicas,
				Message: fmt.Sprintf("%s/%s has %d replicas; rolling restart should preserve capacity", kind, name, replicas),
			})
		}
	}

	share := a.queryTrafficShare(ctx, name, assessment)
	a.setSeverityFromTrafficAndReplicas(assessment, share, replicas)
	a.attachDependents(name, assessment)
	return assessment
}

// assessScale handles `kubectl scale deployment/X --replicas=N -n Y`.
// Scaling to zero is critical regardless of traffic; large reductions are
// high risk.
func (a *assessor) assessScale(ctx context.Context, cmd Command, raw string) *Assessment {
	m := scaleRe.FindStringSubmatch(raw)
	kind, name := m[1], m[2]
	target, _ := strconv.Atoi(m[3])
	ns := pickNamespace(m[4], m[5], cmd.Namespace)

	assessment := &Assessment{
		CommandID:  cmd.ID,
		Confidence: 0.85,
	}

	current := a.queryDeploymentReplicas(ctx, kind, name, ns, assessment)
	share := a.queryTrafficShare(ctx, name, assessment)

	// EstimatedReplicasAffected is the absolute change in replicas.
	delta := current - target
	if delta < 0 {
		delta = -delta
	}
	assessment.EstimatedReplicasAffected = delta

	switch {
	case target == 0 && current > 0:
		assessment.OverallSeverity = SeverityCritical
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("scaling %s/%s from %d to 0 takes the service offline entirely", kind, name, current),
		})
	case current > 0 && target < current && (current-target)*2 > current:
		// reducing more than half
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("scaling %s/%s from %d to %d removes >50%% of capacity", kind, name, current, target),
		})
		// Only set high if traffic-derived severity didn't already say critical.
		if severityRank(assessment.OverallSeverity) < severityRank(SeverityHigh) {
			assessment.OverallSeverity = SeverityHigh
		}
	case current > 0 && target > current:
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("scaling %s/%s up from %d to %d (added capacity)", kind, name, current, target),
		})
	case current == target:
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("scale is a no-op (already at %d replicas)", current),
		})
	}

	// Traffic-derived severity may still upgrade scale-up or partial-down to
	// high/critical if the affected service handles a lot of traffic.
	a.setSeverityFromTrafficAndReplicas(assessment, share, current)
	a.attachDependents(name, assessment)
	return assessment
}

// assessRolloutUndo handles `kubectl rollout undo deployment/X -n Y`. We
// note that this rolls back to the previous image, which in itself is a risk
// signal worth surfacing.
func (a *assessor) assessRolloutUndo(ctx context.Context, cmd Command, raw string) *Assessment {
	m := rolloutUndoRe.FindStringSubmatch(raw)
	kind, name, ns := m[1], m[2], pickNamespace(m[3], m[4], cmd.Namespace)

	assessment := &Assessment{
		CommandID:  cmd.ID,
		Confidence: 0.7,
	}

	replicas := a.queryDeploymentReplicas(ctx, kind, name, ns, assessment)
	if replicas > 0 {
		assessment.EstimatedReplicasAffected = replicas
	}

	assessment.Findings = append(assessment.Findings, Finding{
		Kind:    FindingReplicas,
		Message: fmt.Sprintf("rolls %s/%s back to the previous deployment image", kind, name),
	})

	share := a.queryTrafficShare(ctx, name, assessment)
	a.setSeverityFromTrafficAndReplicas(assessment, share, replicas)
	if severityRank(assessment.OverallSeverity) < severityRank(SeverityMedium) {
		// Rollback is at minimum medium because it changes running code.
		assessment.OverallSeverity = SeverityMedium
	}
	a.attachDependents(name, assessment)
	return assessment
}

// assessDeletePod handles `kubectl delete pod/X -n Y`. Risk is roughly
// 1/replicas of the owning deployment.
func (a *assessor) assessDeletePod(ctx context.Context, cmd Command, raw string) *Assessment {
	m := deletePodRe.FindStringSubmatch(raw)
	pod, ns := m[1], pickNamespace(m[2], m[3], cmd.Namespace)

	assessment := &Assessment{
		CommandID:       cmd.ID,
		Confidence:      0.6,
		OverallSeverity: SeverityMedium,
	}
	assessment.EstimatedReplicasAffected = 1

	// Look up the owning deployment via kube_pod_info so we can compute share.
	deployment := a.queryPodOwner(ctx, pod, ns, assessment)
	if deployment != "" {
		replicas := a.queryDeploymentReplicas(ctx, "deployment", deployment, ns, assessment)
		if replicas > 0 {
			share := 1.0 / float64(replicas)
			assessment.Findings = append(assessment.Findings, Finding{
				Kind: FindingReplicas,
				Message: fmt.Sprintf(
					"deleting pod %s removes ~%.0f%% of %s capacity (%d replicas total)",
					pod, share*100, deployment, replicas,
				),
			})
			if replicas == 1 {
				assessment.OverallSeverity = SeverityHigh
			}
		}
	} else {
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("deleting pod %s/%s; owner deployment unknown", ns, pod),
		})
	}
	return assessment
}

// assessPatch handles `kubectl patch hpa/X` and `kubectl patch configmap/X`.
// These are typically lower-impact, but configmap edits often need a pod
// restart to take effect — we surface that explicitly.
func (a *assessor) assessPatch(_ context.Context, cmd Command, raw string) *Assessment {
	m := patchRe.FindStringSubmatch(raw)
	kind, name := m[1], m[2]

	assessment := &Assessment{
		CommandID:       cmd.ID,
		Confidence:      0.5,
		OverallSeverity: SeverityLow,
	}

	switch strings.ToLower(kind) {
	case "configmap", "cm":
		assessment.OverallSeverity = SeverityMedium
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("patching configmap/%s; pods consuming this map likely need a restart to pick up changes", name),
		})
	case "hpa", "horizontalpodautoscaler":
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("patching hpa/%s adjusts autoscaling thresholds; replica count may change shortly after", name),
		})
	default:
		assessment.Findings = append(assessment.Findings, Finding{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("patching %s/%s", kind, name),
		})
	}
	return assessment
}

// assessSystemctlStop handles `systemctl stop <service>` on a host. Stopping
// a service is critical by default — it's a deliberate outage on that host.
func (a *assessor) assessSystemctlStop(_ context.Context, cmd Command, raw string) *Assessment {
	m := systemctlStopRe.FindStringSubmatch(raw)
	service := m[1]

	return &Assessment{
		CommandID:                 cmd.ID,
		Confidence:                0.7,
		OverallSeverity:           SeverityCritical,
		EstimatedReplicasAffected: 1,
		Findings: []Finding{{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("systemctl stop %s on host %s takes the service offline on this node", service, cmd.Target),
		}},
	}
}

// assessSystemctlRestart handles `systemctl restart <service>` on a host.
// Brief downtime, medium risk by default.
func (a *assessor) assessSystemctlRestart(_ context.Context, cmd Command, raw string) *Assessment {
	m := systemctlRestartRe.FindStringSubmatch(raw)
	service := m[1]

	return &Assessment{
		CommandID:                 cmd.ID,
		Confidence:                0.6,
		OverallSeverity:           SeverityMedium,
		EstimatedReplicasAffected: 1,
		Findings: []Finding{{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("restarting %s on host %s; brief downtime expected", service, cmd.Target),
		}},
	}
}

// assessDiskCleanup handles `find ... -delete` and `rm -f *.log`-style
// commands. These are low-risk by safety-rule design (the validator already
// constrained them to log/tmp targets).
func (a *assessor) assessDiskCleanup(_ context.Context, cmd Command, raw string) *Assessment {
	return &Assessment{
		CommandID:       cmd.ID,
		Confidence:      0.5,
		OverallSeverity: SeverityLow,
		Findings: []Finding{{
			Kind:    FindingReplicas,
			Message: fmt.Sprintf("disk cleanup on host %s; service-level impact unlikely", cmd.Target),
		}},
	}
}

// assessUnknown returns a low-confidence medium severity assessment for any
// command shape we don't have a signal for.
func (a *assessor) assessUnknown(cmd Command) *Assessment {
	a.logger.Info("blast radius: no specific signals for command",
		slog.String("command_id", cmd.ID),
		slog.String("command", cmd.Command),
	)
	return &Assessment{
		CommandID:       cmd.ID,
		Confidence:      0.3,
		OverallSeverity: SeverityMedium,
		Findings: []Finding{{
			Kind:    FindingNoData,
			Message: "no specific blast radius signals available for this command shape",
		}},
	}
}

// ----------------------------------------------------------------------------
// Prometheus query helpers
// ----------------------------------------------------------------------------

// queryDeploymentReplicas returns the current replica count for a workload.
// On any failure it appends a no_data finding, lowers confidence, and
// returns 0.
func (a *assessor) queryDeploymentReplicas(ctx context.Context, kind, name, ns string, assessment *Assessment) int {
	if a.fetcher == nil {
		a.recordNoData(assessment, fmt.Sprintf("replica count for %s/%s unavailable (no Prometheus configured)", kind, name))
		return 0
	}
	// kube-state-metrics exposes this for deployments; statefulsets/daemonsets
	// have parallel metric names. We query the most common variant.
	var query string
	switch strings.ToLower(kind) {
	case "deployment":
		query = fmt.Sprintf(`kube_deployment_status_replicas{deployment=%q,namespace=%q}`, name, ns)
	case "statefulset":
		query = fmt.Sprintf(`kube_statefulset_status_replicas{statefulset=%q,namespace=%q}`, name, ns)
	case "daemonset":
		query = fmt.Sprintf(`kube_daemonset_status_number_ready{daemonset=%q,namespace=%q}`, name, ns)
	case "replicaset":
		query = fmt.Sprintf(`kube_replicaset_status_replicas{replicaset=%q,namespace=%q}`, name, ns)
	default:
		query = fmt.Sprintf(`kube_deployment_status_replicas{deployment=%q,namespace=%q}`, name, ns)
	}

	val, ok := a.queryLatestScalar(ctx, query)
	if !ok {
		a.recordNoData(assessment, fmt.Sprintf("replica count for %s/%s unavailable", kind, name))
		return 0
	}
	if val < 0 {
		val = 0
	}
	return int(val)
}

// queryTrafficShare returns the share (0.0-1.0) of total HTTP traffic the
// named service handles, computed as service_rate / total_rate. On any
// failure it appends a no_data finding and returns 0.
func (a *assessor) queryTrafficShare(ctx context.Context, service string, assessment *Assessment) float64 {
	if a.fetcher == nil {
		return 0
	}
	serviceQuery := fmt.Sprintf(`sum(rate(http_requests_total{service=%q}[5m]))`, service)
	totalQuery := `sum(rate(http_requests_total[5m]))`

	svcRate, svcOk := a.queryLatestScalar(ctx, serviceQuery)
	if !svcOk {
		a.recordNoData(assessment, fmt.Sprintf("traffic share for service %q unavailable", service))
		return 0
	}
	totalRate, totalOk := a.queryLatestScalar(ctx, totalQuery)
	if !totalOk || totalRate <= 0 {
		a.recordNoData(assessment, "total cluster traffic unavailable; cannot compute share")
		return 0
	}

	share := svcRate / totalRate
	if share < 0 {
		share = 0
	}
	if share > 1 {
		share = 1
	}
	assessment.EstimatedTrafficShareBps = share
	assessment.Findings = append(assessment.Findings, Finding{
		Kind:    FindingTraffic,
		Message: fmt.Sprintf("service %q handles ~%.1f%% of cluster HTTP traffic (%.1f req/s)", service, share*100, svcRate),
	})
	return share
}

// queryPodOwner resolves the deployment that owns a pod via kube_pod_info.
// kube_pod_info exposes the pod's controlling owner in the `created_by_name`
// label (the immediate owner is usually a ReplicaSet whose name embeds the
// deployment name; we strip the trailing hash).
func (a *assessor) queryPodOwner(ctx context.Context, pod, ns string, assessment *Assessment) string {
	if a.fetcher == nil {
		return ""
	}
	query := fmt.Sprintf(`kube_pod_info{pod=%q,namespace=%q}`, pod, ns)
	queryCtx, cancel := context.WithTimeout(ctx, a.cfg.PrometheusQueryTimeout)
	defer cancel()

	series, err := a.fetcher.QueryRange(queryCtx, query, time.Now(), 5*time.Minute)
	if err != nil || len(series) == 0 {
		a.recordNoData(assessment, fmt.Sprintf("could not resolve owner of pod %s/%s", ns, pod))
		return ""
	}
	owner := series[0].Labels["created_by_name"]
	// ReplicaSet names look like "<deployment>-<hash>". Strip the trailing
	// segment to get the deployment name. If the format doesn't match we
	// return the raw owner name.
	if idx := strings.LastIndex(owner, "-"); idx > 0 {
		return owner[:idx]
	}
	return owner
}

// queryLatestScalar runs a PromQL query and returns the most recent value
// across all returned series (summed — useful for `sum(...)` queries that
// already produce a single series, and reasonable for scalar-like
// `kube_*_status_replicas` queries which return one or zero series).
func (a *assessor) queryLatestScalar(ctx context.Context, query string) (float64, bool) {
	queryCtx, cancel := context.WithTimeout(ctx, a.cfg.PrometheusQueryTimeout)
	defer cancel()

	series, err := a.fetcher.QueryRange(queryCtx, query, time.Now(), 5*time.Minute)
	if err != nil {
		a.logger.Warn("blast radius prometheus query failed",
			slog.String("query", query),
			slog.String("error", err.Error()),
		)
		return 0, false
	}
	if len(series) == 0 {
		return 0, false
	}
	var sum float64
	var found bool
	for _, s := range series {
		if len(s.DataPoints) == 0 {
			continue
		}
		sum += s.DataPoints[len(s.DataPoints)-1].Value
		found = true
	}
	return sum, found
}

// recordNoData appends a no_data finding and reduces confidence.
func (a *assessor) recordNoData(assessment *Assessment, message string) {
	assessment.Findings = append(assessment.Findings, Finding{
		Kind:    FindingNoData,
		Message: message,
	})
	// Each no_data observation halves remaining confidence, floored at 0.1
	// so a partial assessment still renders meaningfully.
	assessment.Confidence /= 2
	if assessment.Confidence < 0.1 {
		assessment.Confidence = 0.1
	}
}

// setSeverityFromTrafficAndReplicas folds traffic share + replica count into
// the running severity, never lowering an already-set higher severity.
func (a *assessor) setSeverityFromTrafficAndReplicas(assessment *Assessment, share float64, replicas int) {
	var computed string
	switch {
	case share >= a.cfg.CriticalTrafficThreshold:
		computed = SeverityCritical
	case share >= a.cfg.HighTrafficThreshold:
		computed = SeverityHigh
	case share > 0:
		computed = SeverityMedium
	case replicas == 1:
		// No traffic data but only one replica — treat as medium minimum.
		computed = SeverityMedium
	default:
		computed = SeverityLow
	}
	if severityRank(computed) > severityRank(assessment.OverallSeverity) {
		assessment.OverallSeverity = computed
	}
}

// attachDependents looks up the topology graph (if available) and records
// downstream services that depend on the affected one.
func (a *assessor) attachDependents(service string, assessment *Assessment) {
	if a.topology == nil {
		return
	}
	topo := a.topology.Get(service)
	if topo == nil {
		return
	}
	for _, d := range topo.Downstream {
		assessment.DependentServices = append(assessment.DependentServices, d.Name)
	}
	if len(topo.Downstream) > 0 {
		assessment.Findings = append(assessment.Findings, Finding{
			Kind: FindingDownstream,
			Message: fmt.Sprintf("%d downstream service(s) depend on %s: %s",
				len(topo.Downstream), service, summarizeDownstream(topo.Downstream)),
		})
	}
}

// summarizeDownstream renders up to three downstream service names for a
// finding message.
func summarizeDownstream(ds []topology.Downstream) string {
	names := make([]string, 0, len(ds))
	for _, d := range ds {
		names = append(names, d.Name)
		if len(names) == 3 {
			break
		}
	}
	if len(ds) > 3 {
		names = append(names, fmt.Sprintf("(+%d more)", len(ds)-3))
	}
	return strings.Join(names, ", ")
}

// pickNamespace returns the first non-empty namespace among the candidates,
// preferring values parsed from the command itself over the input fallback.
func pickNamespace(parsed1, parsed2, fallback string) string {
	if parsed1 != "" {
		return parsed1
	}
	if parsed2 != "" {
		return parsed2
	}
	if fallback != "" {
		return fallback
	}
	return "default"
}
