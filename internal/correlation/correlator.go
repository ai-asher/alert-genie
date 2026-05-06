package correlation

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/alert-genie/alert-genie/internal/topology"
)

// flushTickInterval is how often the background loop checks the buffer for
// alerts whose deadline has passed. Kept short so the per-alert latency is
// dominated by the configured window, not the tick.
const flushTickInterval = 1 * time.Second

// GroupCallback is invoked once per emitted Group. It is called from the
// background flush goroutine; implementations should not block the caller for
// long (spawn a worker goroutine if heavy work is required).
type GroupCallback func(ctx context.Context, group Group)

// bufferedAlert wraps an Alert with the deadline at which it becomes eligible
// for flushing.
type bufferedAlert struct {
	alert    Alert
	deadline time.Time
}

// Correlator buffers incoming alerts for a configurable window, then groups
// alerts that arrived within the same window into clusters and emits one
// Group per cluster via the registered callback.
//
// A Correlator is safe for concurrent Submit calls. Start must be called
// exactly once; Stop is idempotent.
type Correlator struct {
	window       time.Duration
	maxGroupSize int
	topology     topology.Provider
	onGroup      GroupCallback
	logger       *slog.Logger

	mu     sync.Mutex
	buffer []bufferedAlert

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

// New returns a Correlator that buffers alerts for the given window before
// grouping. The topology provider is optional and used only as a tiebreaker
// when picking the primary alert; pass nil to disable that scoring path.
// maxGroupSize is a hard cap on cluster membership; once reached additional
// alerts in the same logical cluster spill into separate groups. A zero or
// negative value disables the cap.
func New(
	window time.Duration,
	maxGroupSize int,
	topo topology.Provider,
	onGroup GroupCallback,
	logger *slog.Logger,
) *Correlator {
	if window <= 0 {
		window = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Correlator{
		window:       window,
		maxGroupSize: maxGroupSize,
		topology:     topo,
		onGroup:      onGroup,
		logger:       logger,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// Submit places an alert in the buffer with a deadline of now + window. The
// alert will be considered for grouping once the deadline elapses. Submit is
// non-blocking and safe to call from many goroutines.
func (c *Correlator) Submit(ctx context.Context, a Alert) {
	deadline := time.Now().Add(c.window)
	c.mu.Lock()
	c.buffer = append(c.buffer, bufferedAlert{alert: a, deadline: deadline})
	depth := len(c.buffer)
	c.mu.Unlock()
	c.logger.Debug("correlator submit",
		"alert_id", a.ID,
		"alertname", a.AlertName,
		"deadline", deadline.Format(time.RFC3339),
		"buffer_depth", depth,
	)
}

// Start launches the background flush loop. It returns immediately. The loop
// exits when ctx is cancelled or Stop is called, whichever happens first. On
// exit, any remaining buffered alerts are flushed in a final pass so no data
// is lost on shutdown.
func (c *Correlator) Start(ctx context.Context) {
	go c.runLoop(ctx)
}

// Stop signals the flush loop to exit and blocks until it has drained any
// remaining buffered alerts. Calling Stop more than once is a no-op.
func (c *Correlator) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	<-c.doneCh
}

func (c *Correlator) runLoop(ctx context.Context) {
	defer close(c.doneCh)
	ticker := time.NewTicker(flushTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("correlator stopping (context cancelled), flushing remaining buffer")
			c.flushAll(context.Background())
			return
		case <-c.stopCh:
			c.logger.Info("correlator stopping (Stop called), flushing remaining buffer")
			c.flushAll(context.Background())
			return
		case <-ticker.C:
			c.flushDue(ctx)
		}
	}
}

// flushDue drains all alerts whose deadline has passed and dispatches groups.
func (c *Correlator) flushDue(ctx context.Context) {
	now := time.Now()
	due, kept := c.takeDue(now)
	if len(due) == 0 {
		return
	}
	c.dispatch(ctx, due)
	_ = kept // takeDue already wrote kept back to c.buffer
}

// flushAll drains the entire buffer regardless of deadlines (used at shutdown).
func (c *Correlator) flushAll(ctx context.Context) {
	c.mu.Lock()
	buf := c.buffer
	c.buffer = nil
	c.mu.Unlock()
	if len(buf) == 0 {
		return
	}
	alerts := make([]Alert, 0, len(buf))
	for _, b := range buf {
		alerts = append(alerts, b.alert)
	}
	c.dispatch(ctx, alerts)
}

// takeDue partitions the buffer into alerts whose deadline has passed (returned)
// and alerts still pending (written back to c.buffer).
func (c *Correlator) takeDue(now time.Time) ([]Alert, []bufferedAlert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buffer) == 0 {
		return nil, nil
	}
	due := make([]Alert, 0, len(c.buffer))
	kept := c.buffer[:0:0]
	for _, b := range c.buffer {
		if !b.deadline.After(now) {
			due = append(due, b.alert)
		} else {
			kept = append(kept, b)
		}
	}
	c.buffer = kept
	return due, kept
}

// dispatch clusters the given alerts and emits one Group per cluster.
func (c *Correlator) dispatch(ctx context.Context, alerts []Alert) {
	if len(alerts) == 0 {
		return
	}
	clusters := clusterAlerts(alerts)
	c.logger.Info("correlator flushing",
		"alerts", len(alerts),
		"clusters", len(clusters),
	)
	for _, cluster := range clusters {
		// Honour the size cap by splitting oversize clusters into chunks.
		// Chronological order (StartsAt) keeps the first chunk's primary
		// stable across the split, since the split only happens AFTER
		// designating a primary per chunk.
		chunks := splitForCap(cluster, c.maxGroupSize)
		for _, chunk := range chunks {
			group := c.buildGroup(chunk)
			if c.onGroup != nil {
				c.onGroup(ctx, group)
			}
		}
	}
}

// buildGroup selects the primary alert and constructs a Group.
func (c *Correlator) buildGroup(cluster []Alert) Group {
	primaryIdx, reason := c.pickPrimary(cluster)
	primary := cluster[primaryIdx]
	dependents := make([]Alert, 0, len(cluster)-1)
	for i, a := range cluster {
		if i == primaryIdx {
			continue
		}
		dependents = append(dependents, a)
	}
	return Group{
		GroupID:           newGroupID(),
		Primary:           primary,
		Dependents:        dependents,
		CorrelationReason: reason,
		DetectedAt:        time.Now(),
	}
}

// pickPrimary returns the index of the alert chosen as the cluster's root cause
// and a short string describing why. See package docs for the heuristic.
func (c *Correlator) pickPrimary(cluster []Alert) (int, string) {
	if len(cluster) == 1 {
		return 0, "single-alert group"
	}

	// Find the earliest StartsAt.
	earliestIdx := 0
	for i := 1; i < len(cluster); i++ {
		if cluster[i].StartsAt.Before(cluster[earliestIdx].StartsAt) {
			earliestIdx = i
		}
	}
	earliest := cluster[earliestIdx].StartsAt

	// Collect indices that tie at the earliest timestamp.
	ties := []int{}
	for i, a := range cluster {
		if a.StartsAt.Equal(earliest) {
			ties = append(ties, i)
		}
	}

	if len(ties) == 1 {
		// Compute lead time for the reason string.
		secondEarliest := time.Time{}
		for i, a := range cluster {
			if i == earliestIdx {
				continue
			}
			if secondEarliest.IsZero() || a.StartsAt.Before(secondEarliest) {
				secondEarliest = a.StartsAt
			}
		}
		lead := secondEarliest.Sub(earliest)
		key := clusterKeyDescription(cluster)
		return earliestIdx, fmt.Sprintf("primary fired %s before dependents; %s", lead.Round(time.Second), key)
	}

	// Tiebreak: prefer the alert whose service is most depended-upon per
	// topology (count of in-edges). Falls back to alphabetical alertname.
	bestIdx := ties[0]
	bestScore := c.dependencyInDegree(cluster[bestIdx].Service)
	bestUsedTopo := bestScore >= 0
	for _, i := range ties[1:] {
		score := c.dependencyInDegree(cluster[i].Service)
		if score > bestScore {
			bestIdx = i
			bestScore = score
			bestUsedTopo = score >= 0
		} else if score == bestScore {
			// Alphabetical alertname for determinism.
			if cluster[i].AlertName < cluster[bestIdx].AlertName {
				bestIdx = i
			}
		}
	}

	key := clusterKeyDescription(cluster)
	if bestUsedTopo && bestScore > 0 {
		return bestIdx, fmt.Sprintf("multiple alerts fired simultaneously; service %q has the most downstream dependents (%d); %s",
			cluster[bestIdx].Service, bestScore, key)
	}
	return bestIdx, fmt.Sprintf("multiple alerts fired simultaneously; selected by alphabetical alertname; %s", key)
}

// dependencyInDegree returns how many other services list `service` as one of
// their dependencies. The topology.Provider interface only exposes Get(name),
// so we cannot enumerate all services — instead, we look up `service`'s own
// topology entry and count the entries in its Downstream list, which captures
// "services that depend on me" by the schema in topology.example.yaml.
//
// Returns -1 when no topology data is available for the service.
func (c *Correlator) dependencyInDegree(service string) int {
	if c.topology == nil || service == "" {
		return -1
	}
	t := c.topology.Get(service)
	if t == nil {
		return -1
	}
	return len(t.Downstream)
}

// clusterKeyDescription summarises the labels that hold a cluster together,
// used for the human-readable CorrelationReason.
func clusterKeyDescription(cluster []Alert) string {
	if len(cluster) == 0 {
		return ""
	}
	services := uniqueNonEmpty(cluster, func(a Alert) string { return a.Service })
	namespaces := uniqueNonEmpty(cluster, func(a Alert) string { return a.Namespace })
	instances := uniqueNonEmpty(cluster, func(a Alert) string { return a.Instance })

	parts := []string{}
	if len(services) == 1 && services[0] != "" {
		parts = append(parts, fmt.Sprintf("all share service=%s", services[0]))
	} else if len(namespaces) == 1 && namespaces[0] != "" {
		parts = append(parts, fmt.Sprintf("all share namespace=%s", namespaces[0]))
	} else if len(instances) == 1 && instances[0] != "" {
		parts = append(parts, fmt.Sprintf("all share instance=%s", instances[0]))
	} else {
		parts = append(parts, "linked by overlapping service/namespace/instance labels")
	}
	return parts[0]
}

func uniqueNonEmpty(cluster []Alert, pick func(Alert) string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, a := range cluster {
		v := pick(a)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// clusterAlerts groups a slice of alerts using a union-find pass over
// (service, namespace, instance). Two alerts join the same cluster if they
// share at least one non-empty value across those three labels.
//
// Alerts whose service/namespace/instance are all empty become singleton
// clusters (we have no signal to group them).
func clusterAlerts(alerts []Alert) [][]Alert {
	n := len(alerts)
	if n == 0 {
		return nil
	}
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	// Index by each non-empty key value.
	indexFor := func(idx int, value string, bucket map[string][]int) {
		if value == "" {
			return
		}
		bucket[value] = append(bucket[value], idx)
	}
	byService := map[string][]int{}
	byNamespace := map[string][]int{}
	byInstance := map[string][]int{}
	for i, a := range alerts {
		indexFor(i, a.Service, byService)
		indexFor(i, a.Namespace, byNamespace)
		indexFor(i, a.Instance, byInstance)
	}
	for _, idxs := range byService {
		for k := 1; k < len(idxs); k++ {
			union(idxs[0], idxs[k])
		}
	}
	for _, idxs := range byNamespace {
		for k := 1; k < len(idxs); k++ {
			union(idxs[0], idxs[k])
		}
	}
	for _, idxs := range byInstance {
		for k := 1; k < len(idxs); k++ {
			union(idxs[0], idxs[k])
		}
	}

	// Bucket by root, preserving original order.
	buckets := map[int][]Alert{}
	rootOrder := []int{}
	for i, a := range alerts {
		r := find(i)
		if _, ok := buckets[r]; !ok {
			rootOrder = append(rootOrder, r)
		}
		buckets[r] = append(buckets[r], a)
	}
	clusters := make([][]Alert, 0, len(buckets))
	for _, r := range rootOrder {
		clusters = append(clusters, buckets[r])
	}
	return clusters
}

// splitForCap chunks an oversize cluster while preserving chronological
// ordering, so the first chunk still contains the earliest-firing alerts (and
// thus the most likely root cause). When max <= 0 or len(cluster) <= max, the
// input is returned unchanged.
func splitForCap(cluster []Alert, max int) [][]Alert {
	if max <= 0 || len(cluster) <= max {
		return [][]Alert{cluster}
	}
	// Sort a copy by StartsAt ascending so the split is deterministic.
	sorted := make([]Alert, len(cluster))
	copy(sorted, cluster)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].StartsAt.Before(sorted[j].StartsAt)
	})
	out := [][]Alert{}
	for i := 0; i < len(sorted); i += max {
		end := i + max
		if end > len(sorted) {
			end = len(sorted)
		}
		chunk := make([]Alert, end-i)
		copy(chunk, sorted[i:end])
		out = append(out, chunk)
	}
	return out
}

// newGroupID returns a UUID-v4 string for use as a Group.GroupID.
func newGroupID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fall back to a timestamp-based id; collisions are vanishingly
		// unlikely for our scale and the field is non-load-bearing.
		return fmt.Sprintf("grp-%d", time.Now().UnixNano())
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
