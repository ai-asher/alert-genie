package alert

import (
	"sync"
	"time"
)

// Deduplicator tracks alert fingerprints within a time window to suppress
// duplicate alerts from Alertmanager.
type Deduplicator struct {
	window time.Duration

	mu   sync.Mutex
	seen map[string]time.Time // fingerprint -> last seen time

	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewDeduplicator creates a Deduplicator with the given dedup window and starts
// a background goroutine that cleans up expired entries every minute.
func NewDeduplicator(window time.Duration) *Deduplicator {
	d := &Deduplicator{
		window: window,
		seen:   make(map[string]time.Time),
		stopCh: make(chan struct{}),
	}
	go d.cleanup()
	return d
}

// IsDuplicate returns true if the same fingerprint was already seen within the
// configured dedup window relative to startsAt.
func (d *Deduplicator) IsDuplicate(fingerprint string, startsAt time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	lastSeen, ok := d.seen[fingerprint]
	if !ok {
		return false
	}
	return startsAt.Sub(lastSeen) < d.window
}

// MarkSeen records the current time for the given fingerprint.
func (d *Deduplicator) MarkSeen(fingerprint string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen[fingerprint] = time.Now()
}

// Stop terminates the background cleanup goroutine. It is safe to call
// multiple times.
func (d *Deduplicator) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
	})
}

// cleanup runs in a background goroutine, removing entries older than the dedup
// window every minute.
func (d *Deduplicator) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.evictExpired()
		}
	}
}

func (d *Deduplicator) evictExpired() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-d.window)
	for fp, lastSeen := range d.seen {
		if lastSeen.Before(cutoff) {
			delete(d.seen, fp)
		}
	}
}
