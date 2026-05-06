package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// Tests for the heartbeat loop refactored 2026-05-02 to send
// ground-truth metrics per tick (was: hardcoded {"used_bytes": 0}).
// Closes the heartbeat GAP from the storage_provider functional
// contract and pins three behaviors that fix shipped bugs:
//
//   1. used_bytes reflects actual disk usage (operator-console
//      "1.15 MiB vs 444 MiB ledger" discrepancy)
//   2. disk_free_bytes is included so coord can do capacity-aware
//      placement (Yala-class "declared X but full at Y" cases)
//   3. noble_wallet_address self-service via heartbeat (closes
//      known_regressions §2 — was admin-PATCH-only)

// hexMerkle: 128-char hex name, matches store.isHexName.
func hexMerkle(seed int) string {
	digits := []byte("0123456789abcdef")
	out := make([]byte, 128)
	for i := range out {
		out[i] = digits[(seed+i)%16]
	}
	return string(out)
}

// TestBuildPayload_IncludesUsedAndDiskFree pins the wire shape: both
// byte counters always present, even when zero. Coord-side code
// expects both fields; treating an absent disk_free_bytes as "this
// provider doesn't report it" is a reasonable fallback but should
// never be the steady-state for an upgraded operator.
func TestBuildPayload_IncludesUsedAndDiskFree(t *testing.T) {
	body, err := buildPayload(12345, 67890, "", "")
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, body)
	}
	if got["used_bytes"] != float64(12345) {
		t.Errorf("used_bytes=%v, want 12345", got["used_bytes"])
	}
	if got["disk_free_bytes"] != float64(67890) {
		t.Errorf("disk_free_bytes=%v, want 67890", got["disk_free_bytes"])
	}
	if _, present := got["noble_wallet_address"]; present {
		t.Errorf("noble_wallet_address present with empty value, want absent")
	}
}

// TestBuildPayload_ZeroBytesStillIncluded — empty store / full disk
// is a real state worth reporting, not a sentinel that means "skip
// the field." Pin the difference between "empty value" (don't send)
// for the wallet field and "zero value" (send) for the byte fields.
func TestBuildPayload_ZeroBytesStillIncluded(t *testing.T) {
	body, _ := buildPayload(0, 0, "", "")
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if _, present := got["used_bytes"]; !present {
		t.Errorf("used_bytes missing on zero, should be present")
	}
	if _, present := got["disk_free_bytes"]; !present {
		t.Errorf("disk_free_bytes missing on zero, should be present")
	}
}

// TestBuildPayload_NobleWalletIncludedWhenNonEmpty pins the
// self-service contract for known_regressions §2: operator sets
// noble_wallet_address in config, every heartbeat carries it, coord
// keeps the operator's payout target current with no admin in the
// loop.
func TestBuildPayload_NobleWalletIncludedWhenNonEmpty(t *testing.T) {
	const wallet = "noble1r9ljcmr4sal6tpvsveurpchtfvqukwp0jfwzx8"
	body, _ := buildPayload(100, 200, wallet, "")
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if got["noble_wallet_address"] != wallet {
		t.Errorf("noble_wallet_address=%v, want %q", got["noble_wallet_address"], wallet)
	}
}

// TestBuildPayload_NobleWalletAbsentWhenEmpty — defensive: an empty
// wallet field should NOT be sent, because coord treats omission as
// "leave whatever's on file unchanged" but treats empty-string as
// "the operator wants to clear it." A fresh-installed operator who
// hasn't configured their wallet shouldn't blank coord's existing
// record by accident.
func TestBuildPayload_NobleWalletAbsentWhenEmpty(t *testing.T) {
	body, _ := buildPayload(0, 0, "", "")
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if _, present := got["noble_wallet_address"]; present {
		t.Errorf("noble_wallet_address present with empty value: %v", got["noble_wallet_address"])
	}
}

// TestBuildPayload_ProviderVersionIncludedWhenNonEmpty pins the
// fleet-upgrade-visibility contract: every heartbeat from a versioned
// build carries provider_version, so coord can surface fleet state via
// /internal/providers and operators see at a glance who needs to
// upgrade.
func TestBuildPayload_ProviderVersionIncludedWhenNonEmpty(t *testing.T) {
	body, _ := buildPayload(100, 200, "", "provider-v1-1")
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if got["provider_version"] != "provider-v1-1" {
		t.Errorf("provider_version=%v, want %q", got["provider_version"], "provider-v1-1")
	}
}

// TestBuildPayload_ProviderVersionAbsentWhenEmpty — same reasoning as
// the wallet field. A dev build (no Version set via ldflags) shouldn't
// blank coord's record of whatever a previous versioned build reported.
func TestBuildPayload_ProviderVersionAbsentWhenEmpty(t *testing.T) {
	body, _ := buildPayload(100, 200, "", "")
	var got map[string]any
	_ = json.Unmarshal(body, &got)
	if _, present := got["provider_version"]; present {
		t.Errorf("provider_version present with empty value: %v", got["provider_version"])
	}
}

// TestGatherMetrics_ReturnsRealValues exercises the store integration
// — tickHeartbeat depends on this returning ground-truth values.
// Plant known-size objects in the store, assert UsedBytes is the
// reported value.
func TestGatherMetrics_ReturnsRealValues(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	const planted = 4096
	if err := os.WriteFile(filepath.Join(dir, "objects", hexMerkle(0)), make([]byte, planted), 0o644); err != nil {
		t.Fatalf("plant: %v", err)
	}
	usedBytes, diskFreeBytes, errs := gatherMetrics(st)
	if len(errs) != 0 {
		t.Fatalf("unexpected metric errors: %v", errs)
	}
	if usedBytes != int64(planted) {
		t.Errorf("usedBytes=%d, want %d", usedBytes, planted)
	}
	if diskFreeBytes <= 0 {
		t.Errorf("diskFreeBytes=%d, want > 0", diskFreeBytes)
	}
}

// TestTickHeartbeat_PostsCorrectPayloadEndToEnd is the integration-
// shape test. Spin up an httptest.Server that captures the POST body,
// run a single tickHeartbeat against it, assert the captured payload
// matches what the store reports + the wallet from config.
//
// **Regression invariant pinned:** if a future change reverts the
// heartbeat to a hardcoded payload (the pre-2026-05-02 bug), this
// test fails because the server won't see the planted bytes reflected
// in used_bytes.
func TestTickHeartbeat_PostsCorrectPayloadEndToEnd(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New(dir)
	const planted = 8192
	_ = os.WriteFile(filepath.Join(dir, "objects", hexMerkle(0)), make([]byte, planted), 0o644)

	const wallet = "noble1abc123"
	captured := struct {
		mu        sync.Mutex
		body      map[string]any
		path      string
		gotMethod string
		gotCount  int
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.mu.Lock()
		defer captured.mu.Unlock()
		captured.gotCount++
		captured.gotMethod = r.Method
		captured.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &captured.body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	state := &heartbeatState{}
	tickHeartbeat(context.Background(), &http.Client{Timeout: 5 * time.Second},
		srv.URL+"/internal/providers/test-id/heartbeat", st, wallet, "", state)

	captured.mu.Lock()
	defer captured.mu.Unlock()
	if captured.gotCount != 1 {
		t.Fatalf("server saw %d requests, want 1", captured.gotCount)
	}
	if captured.gotMethod != http.MethodPost {
		t.Errorf("method=%s, want POST", captured.gotMethod)
	}
	if captured.path != "/internal/providers/test-id/heartbeat" {
		t.Errorf("path=%s", captured.path)
	}
	if captured.body["used_bytes"] != float64(planted) {
		t.Errorf("body.used_bytes=%v, want %d. Has the heartbeat reverted to a hardcoded payload?",
			captured.body["used_bytes"], planted)
	}
	if dbf, ok := captured.body["disk_free_bytes"]; !ok || dbf == float64(0) {
		t.Errorf("body.disk_free_bytes=%v, want > 0", captured.body["disk_free_bytes"])
	}
	if captured.body["noble_wallet_address"] != wallet {
		t.Errorf("body.noble_wallet_address=%v, want %q", captured.body["noble_wallet_address"], wallet)
	}
}

// TestTickHeartbeat_RecordsSuccessOn2xx + TestTickHeartbeat_RecordsFailureOn5xx
// pin the success/failure bookkeeping that drives the throttled WARN
// log. Pre-2026-05-02 this was tested only by reading the stderr
// output during manual restart; now it's deterministic.

func TestTickHeartbeat_RecordsSuccessOn2xx(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New(dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	state := &heartbeatState{}
	tickHeartbeat(context.Background(), &http.Client{Timeout: 5 * time.Second},
		srv.URL+"/heartbeat", st, "", "", state)
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.everSucceeded {
		t.Errorf("everSucceeded=false after a 200; want true")
	}
	if state.consecFailures != 0 {
		t.Errorf("consecFailures=%d after a 200; want 0", state.consecFailures)
	}
}

func TestTickHeartbeat_RecordsFailureOn5xx(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New(dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	state := &heartbeatState{}
	tickHeartbeat(context.Background(), &http.Client{Timeout: 5 * time.Second},
		srv.URL+"/heartbeat", st, "", "", state)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.consecFailures != 1 {
		t.Errorf("consecFailures=%d after a 500; want 1", state.consecFailures)
	}
	if state.everSucceeded {
		t.Errorf("everSucceeded=true after a 500; want false")
	}
}

// TestTickHeartbeat_RecoveryAfterFailureLogged covers the
// "recovered" log path: failure then success in the same loop should
// flag recovered=true on the second tick.
func TestTickHeartbeat_RecoveryAfterFailureLogged(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New(dir)
	state := &heartbeatState{}

	// First, simulate a successful first tick so subsequent failures
	// can be counted as "in-streak" — recordSuccess's recovered=true
	// requires everSucceeded already true.
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	tickHeartbeat(context.Background(), &http.Client{Timeout: 5 * time.Second},
		srvOK.URL+"/heartbeat", st, "", "", state)
	srvOK.Close()

	// Now: failure → recordFailure increments consecFailures.
	srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	tickHeartbeat(context.Background(), &http.Client{Timeout: 5 * time.Second},
		srvFail.URL+"/heartbeat", st, "", "", state)
	srvFail.Close()
	state.mu.Lock()
	if state.consecFailures != 1 {
		t.Errorf("after failure: consecFailures=%d, want 1", state.consecFailures)
	}
	state.mu.Unlock()

	// Recover: success while consecFailures > 0.
	srvOK2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srvOK2.Close()
	tickHeartbeat(context.Background(), &http.Client{Timeout: 5 * time.Second},
		srvOK2.URL+"/heartbeat", st, "", "", state)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.consecFailures != 0 {
		t.Errorf("after recovery: consecFailures=%d, want 0", state.consecFailures)
	}
	if !state.everSucceeded {
		t.Errorf("after recovery: everSucceeded=false, want true")
	}
}
