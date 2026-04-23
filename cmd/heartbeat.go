package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// Provider heartbeat loop per PROVIDER_SPEC §5.1, ported from the legacy
// `provider/` codebase (commit cec10f9 on branch
// fix/provider-heartbeat-loop). provider-clean was shipped without this
// loop; without periodic touches, coord's placement filter rejects the
// provider as stale within minutes of startup. That was preventing
// bb75a21a from being selected for any new placements despite being
// healthy.
//
// Contract:
//   - POST to {CoordinatorURL}/internal/providers/{ProviderID}/heartbeat
//     every heartbeatInterval seconds. First tick delayed by one full
//     interval so the listener is already up when the loop emits.
//   - Body is `{"used_bytes": <int>}`. Coord treats all fields as optional
//     and refreshes LastHeartbeat on any 2xx response.
//   - Never crashes the provider. Never mutates readiness state. Never
//     stops retrying while the context is live.
//   - WARN on the first failure in a streak and every warnThrottle
//     thereafter; DEBUG otherwise. Success after failure logs "recovered."
//
// Scope of this port: minimal surface. No wallet_address field (provider-
// clean doesn't carry one), no signature, no sequence number. If we later
// need a richer payload we can extend the body; coord-side tolerance for
// extra fields makes this forward-compatible.

const (
	heartbeatInterval = 30 * time.Second
	heartbeatTimeout  = 10 * time.Second
	warnThrottle      = 5 * time.Minute
)

type heartbeatState struct {
	mu             sync.Mutex
	everSucceeded  bool
	consecFailures int
	lastWarnAt     time.Time
}

func (s *heartbeatState) recordSuccess() (first bool, recovered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	first = !s.everSucceeded
	recovered = s.everSucceeded && s.consecFailures > 0
	s.everSucceeded = true
	s.consecFailures = 0
	return
}

func (s *heartbeatState) recordFailure() (shouldWarn bool, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consecFailures++
	count = s.consecFailures
	now := time.Now()
	if s.consecFailures == 1 || now.Sub(s.lastWarnAt) >= warnThrottle {
		s.lastWarnAt = now
		shouldWarn = true
	}
	return
}

// runHeartbeatLoop starts the long-running loop. Caller goroutines it;
// cancel via ctx. coordinatorURL and providerID must both be non-empty,
// or the caller must not invoke this.
func runHeartbeatLoop(ctx context.Context, coordinatorURL, providerID string) {
	endpoint := fmt.Sprintf("%s/internal/providers/%s/heartbeat",
		coordinatorURL, providerID)
	payload, err := json.Marshal(map[string]int64{"used_bytes": 0})
	if err != nil {
		log.Printf("heartbeat: payload marshal failed, loop disabled: %v", err)
		return
	}
	client := &http.Client{Timeout: heartbeatTimeout}
	state := &heartbeatState{}

	log.Printf("heartbeat: loop starting (interval=%s, endpoint=%s, first tick after one interval)",
		heartbeatInterval, endpoint)

	timer := time.NewTimer(heartbeatInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("heartbeat: loop stopping on context cancel")
			return
		case <-timer.C:
			tickHeartbeat(ctx, client, endpoint, payload, state)
			timer.Reset(heartbeatInterval)
		}
	}
}

func tickHeartbeat(ctx context.Context, client *http.Client, endpoint string, payload []byte, state *heartbeatState) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		if warn, n := state.recordFailure(); warn {
			log.Printf("heartbeat: request build failed (consec=%d): %v", n, err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if warn, n := state.recordFailure(); warn {
			log.Printf("heartbeat: send failed (consec=%d): %v", n, err)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if warn, n := state.recordFailure(); warn {
			log.Printf("heartbeat: non-2xx response (consec=%d): status=%d", n, resp.StatusCode)
		}
		return
	}

	first, recovered := state.recordSuccess()
	switch {
	case first:
		log.Printf("heartbeat: first success")
	case recovered:
		log.Printf("heartbeat: recovered after failure")
	}
}
