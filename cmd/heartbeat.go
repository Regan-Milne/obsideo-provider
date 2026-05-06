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

	"github.com/obsideo/obsideo-provider/store"
)

// Provider heartbeat loop per PROVIDER_SPEC §5.1, ported from the legacy
// `provider/` codebase (commit cec10f9 on branch
// fix/provider-heartbeat-loop). provider-clean was shipped without this
// loop; without periodic touches, coord's placement filter rejects the
// provider as stale within minutes of startup.
//
// Contract:
//   - POST to {CoordinatorURL}/internal/providers/{ProviderID}/heartbeat
//     every heartbeatInterval seconds. First tick delayed by one full
//     interval so the listener is already up when the loop emits.
//   - Body is a JSON object built fresh per tick (see buildPayload):
//       used_bytes:           ground-truth from store.UsedBytes()
//       disk_free_bytes:      ground-truth from store.DiskFreeBytes()
//       noble_wallet_address: from config, only included when non-empty
//   - Coord treats every body field as optional and refreshes
//     LastHeartbeat on any 2xx response.
//   - Never crashes the provider. Never mutates readiness state. Never
//     stops retrying while the context is live.
//   - WARN on the first failure in a streak and every warnThrottle
//     thereafter; DEBUG otherwise. Success after failure logs "recovered."
//
// **2026-05-02 changes** (per vault MEMORY/storage_provider.md
// functional contract): payload was hardcoded as `{"used_bytes": 0}`
// at process start. Now computed per tick from store + config so coord
// receives ground truth on every beat. Closes:
//   - "coord ledger says 444 MiB, provider self-reports 1.15 MiB" UX bug
//     visible in the operator console
//   - capacity-aware placement (coord can avoid full providers)
//   - noble_wallet_address self-service (known_regressions §2)

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

// buildPayload assembles the heartbeat JSON body from the values
// passed in. Pulled out as a pure function so the per-tick payload
// shape is testable in isolation (see heartbeat_test.go) without
// having to spin up a real Store.
//
// nobleWallet is included only when non-empty — coord treats omission
// as "leave whatever's on file unchanged," so a fresh-installed
// operator that hasn't set their wallet yet doesn't blank coord's
// existing record. Both byte fields are always included; 0 is a valid
// value (empty store, full disk respectively).
//
// providerVersion is the binary version string set by main.go (e.g.
// "provider-v1-1"). Always included when non-empty so coord can surface
// fleet-wide version state via /internal/providers and operators see
// at-a-glance which providers need to upgrade. Empty (legacy /
// dev-build) is omitted; coord treats omission as "unknown version" and
// flags the provider for upgrade in the admin view.
func buildPayload(usedBytes, diskFreeBytes int64, nobleWallet, providerVersion string) ([]byte, error) {
	body := map[string]any{
		"used_bytes":      usedBytes,
		"disk_free_bytes": diskFreeBytes,
	}
	if nobleWallet != "" {
		body["noble_wallet_address"] = nobleWallet
	}
	if providerVersion != "" {
		body["provider_version"] = providerVersion
	}
	return json.Marshal(body)
}

// gatherMetrics is the per-tick "ask the store what's on disk" step.
// Any individual field that errors falls back to a sentinel value
// rather than failing the whole heartbeat — partial telemetry is
// strictly better than no telemetry. Errors are surfaced to the caller
// for logging at the call site.
func gatherMetrics(s *store.Store) (usedBytes, diskFreeBytes int64, errs []error) {
	if u, err := s.UsedBytes(); err == nil {
		usedBytes = u
	} else {
		errs = append(errs, fmt.Errorf("used_bytes: %w", err))
	}
	if d, err := s.DiskFreeBytes(); err == nil {
		diskFreeBytes = d
	} else {
		errs = append(errs, fmt.Errorf("disk_free_bytes: %w", err))
	}
	return
}

// runHeartbeatLoop starts the long-running loop. Caller goroutines it;
// cancel via ctx. coordinatorURL and providerID must both be non-empty,
// or the caller must not invoke this. st provides per-tick metrics;
// nobleWallet is the operator's payout address (empty = don't send);
// providerVersion is the binary version string (set by main; reported
// every tick so coord knows fleet-wide upgrade state).
func runHeartbeatLoop(ctx context.Context, coordinatorURL, providerID string, st *store.Store, nobleWallet, providerVersion string) {
	endpoint := fmt.Sprintf("%s/internal/providers/%s/heartbeat",
		coordinatorURL, providerID)
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
			tickHeartbeat(ctx, client, endpoint, st, nobleWallet, providerVersion, state)
			timer.Reset(heartbeatInterval)
		}
	}
}

func tickHeartbeat(ctx context.Context, client *http.Client, endpoint string, st *store.Store, nobleWallet, providerVersion string, state *heartbeatState) {
	usedBytes, diskFreeBytes, metricErrs := gatherMetrics(st)
	for _, err := range metricErrs {
		// Per-metric errors are log-only — we still send what we have.
		// Throttled to the same cadence as connection failures so a
		// persistently-broken syscall doesn't flood the logs.
		log.Printf("heartbeat: metric gather warning: %v", err)
	}
	payload, err := buildPayload(usedBytes, diskFreeBytes, nobleWallet, providerVersion)
	if err != nil {
		// json.Marshal of map[string]any with int64 + string values
		// cannot fail in practice. Log + skip the tick if it ever does.
		if warn, n := state.recordFailure(); warn {
			log.Printf("heartbeat: payload marshal failed (consec=%d): %v", n, err)
		}
		return
	}

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
