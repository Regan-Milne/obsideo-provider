package coverage

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// PauseChecker reports whether the provider's circuit breaker is
// currently active. Implemented by *pausectl.State. The Refresher
// intentionally does NOT call this — refresh continues during a pause
// per design §4.4 — but it is exposed here as the canonical seam for
// future prune-decision code (Phase 2) to consult. Keeping the type
// here avoids an import cycle between coverage and pausectl while
// documenting the gate at a stable location.
type PauseChecker interface {
	IsPaused(now time.Time) bool
}

// Refresher orchestrates periodic coverage-cache refresh:
//   1. List all held merkle roots on local disk.
//   2. Batch them at Client.BatchSize; query the coord per batch.
//   3. For each root in each successful response, call store.UpdateCoverage
//      with the answer (coverage cache handles the first-seen transition).
//   4. On batch failure, log and skip: the prior cache state is preserved
//      (retain-everything per design §6.6).
//
// The Refresher is safe for concurrent RunOnce calls per instance, because
// store.UpdateCoverage is file-atomic and each Put handles its own lock.
// In practice the Start loop runs one cycle at a time.
//
// Circuit breaker: Refresher does not check pause state. Per design
// §4.4, a pause halts coverage-driven *prune decisions*, not cache
// reads — the cache must keep tracking coord truth so that when the
// pause lifts, prune decisions act on current data, not stale data
// from the moment the pause began. Future prune code is the gate site.
type Refresher struct {
	Store     *store.Store
	Client    *Client
	Interval  time.Duration
	BatchSize int

	// Logger is optional; nil uses the standard library log package.
	Logger *log.Logger
}

// Start runs Refresher's cycle in a loop until ctx is canceled. The first
// cycle runs immediately on Start; subsequent cycles wait Interval between.
//
// Start does not return until ctx.Done(); callers goroutine it from the
// daemon startup and cancel via ctx to shut down cleanly.
func (r *Refresher) Start(ctx context.Context) {
	r.logf("coverage refresher started (interval=%s, batch=%d)", r.Interval, r.BatchSize)
	// Run once at startup so the cache is populated before the first
	// interval elapses.
	if err := r.RunOnce(ctx); err != nil {
		r.logf("coverage: initial refresh failed: %v", err)
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logf("coverage refresher stopping: %v", ctx.Err())
			return
		case <-t.C:
			if err := r.RunOnce(ctx); err != nil {
				r.logf("coverage refresh failed: %v", err)
			}
		}
	}
}

// RunOnce performs a single full refresh pass over every held root and
// returns. Safe to call directly for ops-triggered refreshes and tests.
//
// Individual batch failures are logged and do NOT abort the run; other
// batches still get their chance. The returned error is non-nil only on
// pre-batch errors (e.g., failing to list held roots).
func (r *Refresher) RunOnce(ctx context.Context) error {
	roots, err := r.Store.List()
	if err != nil {
		return fmt.Errorf("list held roots: %w", err)
	}
	if len(roots) == 0 {
		r.logf("coverage: no held roots to refresh")
		return nil
	}

	batchSize := r.BatchSize
	if batchSize <= 0 {
		batchSize = 500
	}

	total := len(roots)
	updated := 0
	failed := 0

	for i := 0; i < total; i += batchSize {
		end := i + batchSize
		if end > total {
			end = total
		}
		batch := roots[i:end]

		resp, err := r.Client.QueryRoots(ctx, batch)
		if err != nil {
			// Retain-everything per design §6.6: do not touch the cache
			// for this batch. Prior coverage entries keep their current
			// state; roots with no prior entry stay missing, which the
			// downstream prune-decision logic treats as "retain."
			failed += len(batch)
			r.logf("coverage: batch %d..%d failed (retaining prior state): %v", i, end, err)
			continue
		}

		now := time.Now().UTC()
		for _, root := range batch {
			ans, present := resp[root]
			if !present {
				// Coord did not include this root in the response. Treat
				// as a per-root failure: preserve prior state.
				failed++
				continue
			}
			update := store.CoverageAnswer{
				Status:     ans.Status,
				Contracted: ans.Contracted,
				Until:      ans.Until,
				Reason:     ans.Reason,
			}
			if err := r.Store.UpdateCoverage(root, update, now); err != nil {
				failed++
				r.logf("coverage: update %s failed: %v", root[:min(8, len(root))], err)
				continue
			}
			updated++
		}
	}

	r.logf("coverage refresh complete: total=%d updated=%d failed=%d", total, updated, failed)
	return nil
}

func (r *Refresher) logf(format string, args ...any) {
	if r.Logger != nil {
		r.Logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}
