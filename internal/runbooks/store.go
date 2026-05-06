package runbooks

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Store is the in-memory cache of loaded runbooks. It supports atomic
// snapshot replacement (reload) so retrievers always see a consistent set
// of runbooks even while a reload is mid-flight.
//
// Implementation note: we hold the slice behind an atomic.Pointer so reads
// (Snapshot) are lock-free. The mutex only serializes concurrent reloads,
// which we don't expect in practice (one reload goroutine), but it keeps
// the manual Reload() method safe for tests.
type Store struct {
	loader Loader
	logger *slog.Logger

	current atomic.Pointer[[]*Runbook]
	mu      sync.Mutex // serializes Reload calls
}

// NewStore constructs an empty Store. Call Reload (or Start) to populate
// it. Reading via Snapshot before the first successful reload returns nil.
func NewStore(loader Loader, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	return &Store{loader: loader, logger: logger}
}

// Snapshot returns the current set of runbooks. The returned slice MUST NOT
// be modified by callers — it's shared with all concurrent readers.
func (s *Store) Snapshot() []*Runbook {
	p := s.current.Load()
	if p == nil {
		return nil
	}
	return *p
}

// Reload triggers a synchronous reload of the underlying loader. It's safe
// to call concurrently with Retrieve calls; readers continue to see the
// previous snapshot until this method swaps in the new one.
//
// On loader error: if any runbooks were returned alongside the error, the
// store still swaps them in (partial reload — better than going stale).
// If zero runbooks were returned, the previous snapshot is preserved.
func (s *Store) Reload(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rbs, err := s.loader.Load(ctx)
	if err != nil {
		if len(rbs) == 0 {
			s.logger.Error("runbook reload failed, keeping previous snapshot", "error", err)
			return err
		}
		s.logger.Warn("runbook reload had errors, applying partial snapshot",
			"runbooks", len(rbs), "error", err)
	}
	s.current.Store(&rbs)
	s.logger.Info("runbook snapshot refreshed", "count", len(rbs))
	return err
}

// Start kicks off a background reload loop on the given interval. The
// initial reload runs synchronously before the goroutine starts, so the
// caller can rely on Snapshot returning real data immediately on success.
//
// The loop exits when ctx is cancelled. Errors during reload are logged
// (the store retains its last good snapshot), so callers don't need to
// handle them.
func (s *Store) Start(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	// Initial synchronous load so we don't serve a "no runbooks" prompt
	// for the first 5 minutes after startup.
	if err := s.Reload(ctx); err != nil {
		// Don't fail startup — runbooks are an enrichment, not a hard
		// dependency. The reload loop will retry.
		s.logger.Warn("initial runbook load failed, will retry", "error", err)
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				s.logger.Debug("runbook reload loop exiting", "reason", ctx.Err())
				return
			case <-ticker.C:
				// Use a fresh, bounded context per reload so a stuck
				// filesystem call can't wedge the goroutine forever.
				rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				_ = s.Reload(rctx)
				cancel()
			}
		}
	}()

	return nil
}
