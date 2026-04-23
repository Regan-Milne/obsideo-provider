package coverage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Regan-Milne/obsideo-provider/store"
)

// ----- Test harness -----

// newTempStoreWithObjects creates a Store and calls Put for each of the
// given merkle roots so the Refresher's List() sees them.
func newTempStoreWithObjects(t *testing.T, merkles ...string) *store.Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "refresher-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range merkles {
		if err := st.Put(m, []byte("payload"), store.DefaultChunkSize); err != nil {
			t.Fatalf("store.Put %s: %v", m, err)
		}
	}
	return st
}

// mockCoord returns an httptest.Server whose handler is controlled by the
// caller's function, plus a pointer to a counter that records every request.
func mockCoord(handler http.HandlerFunc) (*httptest.Server, *int32) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	return srv, &hits
}

// zeroRetryClient returns a Client with instant retries so tests run fast.
// BackoffFloor is 1ns; Ceiling is 1ns; MaxRetries matches the arg.
func zeroRetryClient(srv *httptest.Server, maxRetries int) *Client {
	return &Client{
		CoordURL:       srv.URL,
		APIKey:         "test-key",
		HTTP:           srv.Client(),
		MaxRetries:     maxRetries,
		BackoffFloor:   time.Nanosecond,
		BackoffCeiling: time.Nanosecond,
	}
}

// ----- Happy path: refresh populates coverage cache -----

func TestRefresher_RunOnce_PopulatesCoverage(t *testing.T) {
	merkles := []string{
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
	}
	st := newTempStoreWithObjects(t, merkles...)

	srv, hits := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/provider/roots/status" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)

		resp := Response{}
		for _, root := range req.Roots {
			// First merkle covered, second uncovered (mixed answer).
			if strings.HasPrefix(root, "a") {
				resp[root] = RootStatus{Status: "covered", Until: "2026-06-01T00:00:00Z"}
			} else {
				resp[root] = RootStatus{Status: "uncovered", Reason: "contract_expired"}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer srv.Close()

	r := &Refresher{Store: st, Client: zeroRetryClient(srv, 0), Interval: time.Hour, BatchSize: 500}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Errorf("expected 1 coord hit, got %d", atomic.LoadInt32(hits))
	}
	a, err := st.GetCoverage(merkles[0])
	if err != nil || a.Status != "covered" {
		t.Errorf("a-root: %+v err=%v", a, err)
	}
	b, err := st.GetCoverage(merkles[1])
	if err != nil || b.Status != "uncovered" || b.FirstSeenUncovered == nil {
		t.Errorf("b-root: %+v err=%v", b, err)
	}
}

// ----- Batching: multiple batches when roots exceed BatchSize -----

func TestRefresher_RunOnce_SplitsIntoBatches(t *testing.T) {
	// 12 roots, BatchSize 5 → 3 requests (5+5+2).
	merkles := make([]string, 12)
	for i := range merkles {
		merkles[i] = fixedWidthHex(i)
	}
	st := newTempStoreWithObjects(t, merkles...)

	var batchSizes []int
	srv, hits := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)
		batchSizes = append(batchSizes, len(req.Roots))

		resp := Response{}
		for _, root := range req.Roots {
			resp[root] = RootStatus{Status: "covered"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer srv.Close()

	r := &Refresher{Store: st, Client: zeroRetryClient(srv, 0), Interval: time.Hour, BatchSize: 5}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 3 {
		t.Errorf("expected 3 requests; got %d", got)
	}
	// Order isn't guaranteed by Store.List, so just check the multiset.
	// First two batches should be full (5), last should be 2.
	totalCovered := 0
	for _, sz := range batchSizes {
		totalCovered += sz
	}
	if totalCovered != 12 {
		t.Errorf("sum of batch sizes = %d, want 12", totalCovered)
	}
}

// ----- Retain-everything: coord 5xx leaves prior cache state alone -----

func TestRefresher_RetainsPriorState_OnCoord5xx(t *testing.T) {
	// This is the load-bearing retain-everything behavior from §6.6.
	// Seed a prior covered answer for a root, then have the coord return
	// 500 on refresh. The cache MUST stay covered.
	merkle := strings.Repeat("f", 64)
	st := newTempStoreWithObjects(t, merkle)

	// Seed prior covered state.
	priorTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := st.UpdateCoverage(merkle,
		store.CoverageAnswer{Status: "covered", Until: "2026-06-01T00:00:00Z"},
		priorTime); err != nil {
		t.Fatal(err)
	}

	srv, _ := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "simulated outage", http.StatusInternalServerError)
	})
	defer srv.Close()

	r := &Refresher{Store: st, Client: zeroRetryClient(srv, 2), Interval: time.Hour, BatchSize: 500}
	// RunOnce returns nil (pre-batch succeeded; batch-level failure is logged but not fatal).
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Cache state MUST be unchanged.
	got, err := st.GetCoverage(merkle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "covered" {
		t.Errorf("status = %q, want covered (retain-everything preserves prior)", got.Status)
	}
	if !got.RefreshedAt.Equal(priorTime) {
		t.Errorf("refreshed_at = %v, want %v (NOT updated on refresh failure)", got.RefreshedAt, priorTime)
	}
	if got.FirstSeenUncovered != nil {
		t.Errorf("refresh failure must not set FirstSeenUncovered; got %v", got.FirstSeenUncovered)
	}
}

// ----- Retain-everything: coord returns some roots missing from response -----

func TestRefresher_RetainsPriorState_WhenRootOmittedFromResponse(t *testing.T) {
	// Per-root resilience: if the coord returns a partial answer (some
	// roots missing), ONLY the roots present in the response get their
	// cache updated. Missing roots keep prior state.
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	st := newTempStoreWithObjects(t, a, b)

	priorTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = st.UpdateCoverage(b, store.CoverageAnswer{Status: "covered"}, priorTime)

	srv, _ := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)
		resp := Response{}
		// Only answer for root `a`; omit `b`.
		for _, root := range req.Roots {
			if strings.HasPrefix(root, "a") {
				resp[root] = RootStatus{Status: "uncovered", Reason: "contract_expired"}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer srv.Close()

	r := &Refresher{Store: st, Client: zeroRetryClient(srv, 0), Interval: time.Hour, BatchSize: 500}
	_ = r.RunOnce(context.Background())

	// Root a: updated to uncovered.
	aRes, _ := st.GetCoverage(a)
	if aRes.Status != "uncovered" {
		t.Errorf("a.status = %q, want uncovered", aRes.Status)
	}
	// Root b: prior state preserved.
	bRes, _ := st.GetCoverage(b)
	if bRes.Status != "covered" {
		t.Errorf("b.status = %q, want covered (preserved, absent from response)", bRes.Status)
	}
	if !bRes.RefreshedAt.Equal(priorTime) {
		t.Errorf("b.refreshed_at = %v, want %v (not touched)", bRes.RefreshedAt, priorTime)
	}
}

// ----- Retry on 5xx eventually succeeds -----

func TestRefresher_Retries5xxThenSucceeds(t *testing.T) {
	merkle := strings.Repeat("7", 64)
	st := newTempStoreWithObjects(t, merkle)

	var attempts int32
	srv, _ := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			http.Error(w, "transient", http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req Request
		_ = json.Unmarshal(body, &req)
		resp := Response{}
		for _, root := range req.Roots {
			resp[root] = RootStatus{Status: "covered", Until: "2026-06-01T00:00:00Z"}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer srv.Close()

	r := &Refresher{Store: st, Client: zeroRetryClient(srv, 5), Interval: time.Hour, BatchSize: 500}
	_ = r.RunOnce(context.Background())

	got, err := st.GetCoverage(merkle)
	if err != nil || got.Status != "covered" {
		t.Errorf("after retry: got=%+v err=%v", got, err)
	}
	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected exactly 3 attempts (2 failures + 1 success); got %d", attempts)
	}
}

// ----- No roots: no requests made -----

func TestRefresher_NoHeldRoots_NoRequests(t *testing.T) {
	st := newTempStoreWithObjects(t)
	srv, hits := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	r := &Refresher{Store: st, Client: zeroRetryClient(srv, 0), Interval: time.Hour, BatchSize: 500}
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Errorf("expected 0 hits; got %d", got)
	}
}

// ----- Non-retryable 4xx short-circuits retries -----

func TestClient_QueryRoots_4xxIsNotRetried(t *testing.T) {
	var hits int32
	srv, _ := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	defer srv.Close()
	c := zeroRetryClient(srv, 5)
	_, err := c.QueryRoots(context.Background(), []string{"deadbeef"})
	if !errors.Is(err, ErrNonRetryable) {
		t.Errorf("want ErrNonRetryable; got %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("4xx must short-circuit retries; got %d attempts", got)
	}
}

// ----- Context cancellation between retries -----

func TestClient_QueryRoots_ContextCancelStopsRetries(t *testing.T) {
	srv, _ := mockCoord(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	})
	defer srv.Close()

	// Slow retry so the cancel has time to land between attempts.
	c := &Client{
		CoordURL:       srv.URL,
		APIKey:         "",
		HTTP:           srv.Client(),
		MaxRetries:     10,
		BackoffFloor:   50 * time.Millisecond,
		BackoffCeiling: 50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.QueryRoots(ctx, []string{"d"})
	if err == nil {
		t.Fatal("expected error on cancel")
	}
}

// fixedWidthHex produces a 64-char hex-like string for test merkles.
func fixedWidthHex(n int) string {
	base := strings.Repeat("0", 60)
	return base + hexChars(n)
}

func hexChars(n int) string {
	s := ""
	for i := 0; i < 4; i++ {
		d := n % 16
		var c byte
		if d < 10 {
			c = byte('0' + d)
		} else {
			c = byte('a' + d - 10)
		}
		s = string(c) + s
		n /= 16
	}
	return s
}
