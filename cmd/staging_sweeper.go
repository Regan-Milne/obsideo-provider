package cmd

import (
	"context"
	"log"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// Staging-cruft sweeper: a background loop that periodically prunes
// chunked-upload staging dirs older than stagingMaxAge. Runs at
// stagingSweepInterval cadence for the lifetime of the process; ctx
// cancel terminates the loop.
//
// Closes the orphan-staging loop that was the most-likely cause of
// the Yala-class case where declared capacity ≠ writable space —
// every failed chunked upload leaves a partial staging dir behind
// (~95 MB per failed attempt at 1MB chunks × 95 chunks before chunk
// 96 hits a 5xx). Across multiple failed runs these accumulate
// untracked, eventually filling the disk while coord still thinks
// the provider has room.
//
// Idempotent: an empty staging dir is a no-op. Per-cycle errors are
// logged but never fatal — sweeper keeps running on the next tick.

const (
	stagingMaxAge         = 1 * time.Hour
	stagingSweepInterval  = 1 * time.Hour
)

func runStagingSweeper(ctx context.Context, st *store.Store) {
	log.Printf("staging sweeper: starting (interval=%s, max_age=%s)", stagingSweepInterval, stagingMaxAge)
	timer := time.NewTimer(stagingSweepInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("staging sweeper: stopping on context cancel")
			return
		case <-timer.C:
			tickStagingSweeper(st)
			timer.Reset(stagingSweepInterval)
		}
	}
}

func tickStagingSweeper(st *store.Store) {
	cleaned, err := st.SweepStaleStaging(stagingMaxAge)
	if err != nil {
		log.Printf("staging sweeper: %v (cleaned=%d this cycle)", err, cleaned)
		return
	}
	if cleaned > 0 {
		log.Printf("staging sweeper: pruned %d stale staging dir(s)", cleaned)
	}
}
