package dirfetch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/tokens"
)

// signedDirectory builds a signed directory envelope using the same
// canonicalization rules as the coord (sorted keys via map round-trip).
// Returned bytes are exactly what the coord's Snapshotter would emit
// for the given inputs.
func signedDirectory(t *testing.T, coordPub ed25519.PublicKey, coordPriv ed25519.PrivateKey, dcSigners []ed25519.PublicKey) []byte {
	t.Helper()

	signers := []string{base64.StdEncoding.EncodeToString(coordPub)}
	for _, k := range dcSigners {
		signers = append(signers, base64.StdEncoding.EncodeToString(k))
	}

	payload := map[string]any{
		"timestamp":          "2026-05-08T17:00:00Z",
		"version":            "directory-v1",
		"providers":          []any{},
		"authorized_signers": signers,
	}
	canon, err := canonicalMarshal(payload)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	sig := ed25519.Sign(coordPriv, canon)

	envelope := make(map[string]any, len(payload)+1)
	for k, v := range payload {
		envelope[k] = v
	}
	envelope["signature"] = base64.StdEncoding.EncodeToString(sig)
	out, err := canonicalMarshal(envelope)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return out
}

// fakeCoord is a minimal HTTP server that responds to GET
// /v1/provider/directory with whatever bytes it's been configured to
// serve. Concurrency-safe so tests can swap the response body
// mid-loop.
type fakeCoord struct {
	mu       sync.RWMutex
	body     []byte
	status   int
	requests int
	gotAuth  []string
}

func (f *fakeCoord) setBody(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = b
	f.status = http.StatusOK
}

func (f *fakeCoord) setStatus(code int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = []byte(body)
	f.status = code
}

func (f *fakeCoord) reqCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.requests
}

func (f *fakeCoord) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests++
		f.gotAuth = append(f.gotAuth, r.Header.Get("Authorization"))
		body := f.body
		status := f.status
		f.mu.Unlock()
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
}

// captureLogger collects Printf calls so tests can assert on
// log output (or just discard).
type captureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (c *captureLogger) Printf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *captureLogger) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

// newTestSetup wires a fakeCoord + Refresher backed by a fresh Verifier
// seeded with the coord's pubkey (matches real provider startup where
// tokens.NewVerifier loads coord_pub.pem).
func newTestSetup(t *testing.T) (*fakeCoord, *Refresher, *tokens.Verifier, ed25519.PublicKey, ed25519.PrivateKey, *captureLogger) {
	t.Helper()
	coordPub, coordPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate coord key: %v", err)
	}
	verifier := tokens.NewVerifierForTesting(coordPub)
	fake := &fakeCoord{}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	logger := &captureLogger{}
	r, err := New(Options{
		CoordURL:    srv.URL,
		APIKey:      "provider-key-abc",
		CoordPubKey: coordPub,
		Verifier:    verifier,
		Interval:    50 * time.Millisecond,
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fake, r, verifier, coordPub, coordPriv, logger
}

func TestNew_ValidatesRequiredFields(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := tokens.NewVerifierForTesting(pub)
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"empty url", Options{APIKey: "k", CoordPubKey: pub, Verifier: v}, "CoordURL"},
		{"empty apikey", Options{CoordURL: "http://x", CoordPubKey: pub, Verifier: v}, "APIKey"},
		{"bad pubkey size", Options{CoordURL: "http://x", APIKey: "k", CoordPubKey: []byte{1, 2, 3}, Verifier: v}, "CoordPubKey"},
		{"nil verifier", Options{CoordURL: "http://x", APIKey: "k", CoordPubKey: pub}, "Verifier"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := New(tc.opts)
			if err == nil || r != nil {
				t.Fatalf("expected error containing %q, got r=%v err=%v", tc.want, r, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q missing %q", err.Error(), tc.want)
			}
		})
	}
}

func TestRefreshOnce_AddsNewSigners(t *testing.T) {
	fake, r, verifier, coordPub, coordPriv, _ := newTestSetup(t)

	dcAPub, _, _ := ed25519.GenerateKey(rand.Reader)
	dcBPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fake.setBody(signedDirectory(t, coordPub, coordPriv, []ed25519.PublicKey{dcAPub, dcBPub}))

	added, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2", added)
	}
	if !verifier.HasKey(dcAPub) {
		t.Error("DC A pubkey missing from verifier after refresh")
	}
	if !verifier.HasKey(dcBPub) {
		t.Error("DC B pubkey missing from verifier after refresh")
	}
	if verifier.KeyCount() != 3 { // coord seed + 2 DCs
		t.Errorf("KeyCount = %d, want 3", verifier.KeyCount())
	}
}

// TestRefreshOnce_Idempotent pins the bucket-lifetime / no-rotation
// semantics: a refresh that re-observes existing keys must not grow
// the trust list, and must not flag them as added.
func TestRefreshOnce_Idempotent(t *testing.T) {
	fake, r, verifier, coordPub, coordPriv, _ := newTestSetup(t)

	dcPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fake.setBody(signedDirectory(t, coordPub, coordPriv, []ed25519.PublicKey{dcPub}))

	if added, err := r.RefreshOnce(context.Background()); err != nil || added != 1 {
		t.Fatalf("first refresh: added=%d err=%v", added, err)
	}
	if added, err := r.RefreshOnce(context.Background()); err != nil || added != 0 {
		t.Errorf("second refresh: added=%d err=%v (want 0)", added, err)
	}
	if verifier.KeyCount() != 2 {
		t.Errorf("KeyCount after duplicate refresh = %d, want 2", verifier.KeyCount())
	}
}

// TestRefreshOnce_RejectsBadSignature pins the fail-closed rule: a
// directory whose signature doesn't verify against the provider's
// coord pubkey must not modify the trust list. The provider keeps
// running on its previous (verified) trust state.
func TestRefreshOnce_RejectsBadSignature(t *testing.T) {
	fake, r, verifier, _, _, _ := newTestSetup(t)

	// Build a directory signed by an UNTRUSTED key — the refresher
	// should reject it because the signature won't verify against the
	// coord pubkey it has on file.
	rougePub, rougePriv, _ := ed25519.GenerateKey(rand.Reader)
	dcPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fake.setBody(signedDirectory(t, rougePub, rougePriv, []ed25519.PublicKey{dcPub}))

	preCount := verifier.KeyCount()
	added, err := r.RefreshOnce(context.Background())
	if err == nil {
		t.Fatal("RefreshOnce accepted directory signed by untrusted key")
	}
	if !strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("error %q missing 'signature invalid'", err.Error())
	}
	if added != 0 {
		t.Errorf("added = %d, want 0 on bad-sig refresh", added)
	}
	if verifier.KeyCount() != preCount {
		t.Errorf("KeyCount changed under bad-sig refresh: was %d, now %d (must be unchanged — fail-closed)",
			preCount, verifier.KeyCount())
	}
	if verifier.HasKey(dcPub) {
		t.Error("DC pubkey was added under bad-sig refresh — must not be")
	}
}

// TestRefreshOnce_LegacyDirectoryFormat covers the backwards-compat
// path: a directory missing the authorized_signers field (pre-Phase-1
// snapshotter output) is treated as empty. No new keys to add, no
// error. The provider's seed pubkey from PEM keeps working.
func TestRefreshOnce_LegacyDirectoryFormat(t *testing.T) {
	fake, r, verifier, coordPub, coordPriv, _ := newTestSetup(t)

	// Build a legacy-shape envelope with no authorized_signers field.
	payload := map[string]any{
		"timestamp": "2026-05-08T17:00:00Z",
		"version":   "directory-v1",
		"providers": []any{},
	}
	canon, _ := canonicalMarshal(payload)
	sig := ed25519.Sign(coordPriv, canon)
	envelope := make(map[string]any, len(payload)+1)
	for k, v := range payload {
		envelope[k] = v
	}
	envelope["signature"] = base64.StdEncoding.EncodeToString(sig)
	body, _ := canonicalMarshal(envelope)
	fake.setBody(body)

	preCount := verifier.KeyCount()
	added, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("legacy directory: %v", err)
	}
	if added != 0 {
		t.Errorf("added = %d, want 0 (legacy directory has no authorized_signers)", added)
	}
	if verifier.KeyCount() != preCount {
		t.Errorf("KeyCount changed on legacy directory: was %d, now %d", preCount, verifier.KeyCount())
	}
	_ = coordPub
}

func TestRefreshOnce_HTTPErrorPropagates(t *testing.T) {
	fake, r, verifier, _, _, _ := newTestSetup(t)
	fake.setStatus(http.StatusServiceUnavailable, "coord unavailable")
	preCount := verifier.KeyCount()

	added, err := r.RefreshOnce(context.Background())
	if err == nil {
		t.Fatal("expected error on 503 response")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error %q missing 503", err.Error())
	}
	if added != 0 {
		t.Errorf("added = %d, want 0 on HTTP error", added)
	}
	if verifier.KeyCount() != preCount {
		t.Errorf("KeyCount changed under HTTP error: was %d, now %d", preCount, verifier.KeyCount())
	}
}

func TestRefreshOnce_SkipsMalformedSignerEntries(t *testing.T) {
	fake, r, verifier, coordPub, coordPriv, _ := newTestSetup(t)

	// Build an envelope with a mix of valid/invalid signer entries.
	dcPub, _, _ := ed25519.GenerateKey(rand.Reader)
	signers := []string{
		base64.StdEncoding.EncodeToString(coordPub),  // valid coord
		base64.StdEncoding.EncodeToString(dcPub),     // valid DC
		"!!! not base64 !!!",                         // malformed
		base64.StdEncoding.EncodeToString([]byte{1}), // wrong size (1 byte)
	}
	payload := map[string]any{
		"timestamp":          "2026-05-08T17:00:00Z",
		"version":            "directory-v1",
		"providers":          []any{},
		"authorized_signers": signers,
	}
	canon, _ := canonicalMarshal(payload)
	sig := ed25519.Sign(coordPriv, canon)
	envelope := make(map[string]any, len(payload)+1)
	for k, v := range payload {
		envelope[k] = v
	}
	envelope["signature"] = base64.StdEncoding.EncodeToString(sig)
	body, _ := canonicalMarshal(envelope)
	fake.setBody(body)

	added, err := r.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	// Only the DC pubkey is new (coord pubkey was already in the seed).
	if added != 1 {
		t.Errorf("added = %d, want 1 (only DC; coord was seeded; malformed entries skipped)", added)
	}
	if !verifier.HasKey(dcPub) {
		t.Error("DC pubkey missing after refresh with mixed-validity entries")
	}
}

func TestRefreshOnce_SendsBearerAuth(t *testing.T) {
	fake, r, _, coordPub, coordPriv, _ := newTestSetup(t)
	fake.setBody(signedDirectory(t, coordPub, coordPriv, nil))

	if _, err := r.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	fake.mu.RLock()
	defer fake.mu.RUnlock()
	if len(fake.gotAuth) == 0 {
		t.Fatal("no requests recorded")
	}
	want := "Bearer provider-key-abc"
	if fake.gotAuth[0] != want {
		t.Errorf("Authorization header = %q, want %q", fake.gotAuth[0], want)
	}
}

// TestStart_PicksUpNewSignerOnInterval pins the integration-style
// behavior: the refresher loop picks up a newly-registered DC pubkey
// on the next tick without restart, and the provider's Verifier
// starts accepting tokens signed by that DC.
func TestStart_PicksUpNewSignerOnInterval(t *testing.T) {
	fake, r, verifier, coordPub, coordPriv, _ := newTestSetup(t)

	// Initial directory: no DCs registered.
	fake.setBody(signedDirectory(t, coordPub, coordPriv, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go r.Start(ctx)

	// Wait briefly for initial refresh to land.
	time.Sleep(75 * time.Millisecond)
	if verifier.KeyCount() != 1 {
		t.Fatalf("after initial refresh: KeyCount = %d, want 1 (just coord seed)", verifier.KeyCount())
	}

	// Register a DC: rotate the directory body. Next tick (50ms) picks it up.
	dcPub, _, _ := ed25519.GenerateKey(rand.Reader)
	fake.setBody(signedDirectory(t, coordPub, coordPriv, []ed25519.PublicKey{dcPub}))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if verifier.HasKey(dcPub) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !verifier.HasKey(dcPub) {
		t.Fatalf("DC pubkey not picked up after registration; requests=%d, KeyCount=%d", fake.reqCount(), verifier.KeyCount())
	}
}

func TestStart_StopsOnContextCancel(t *testing.T) {
	fake, r, _, coordPub, coordPriv, _ := newTestSetup(t)
	fake.setBody(signedDirectory(t, coordPub, coordPriv, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Start(ctx)
		close(done)
	}()
	time.Sleep(75 * time.Millisecond) // let it run a couple of cycles
	cancel()

	select {
	case <-done:
		// loop exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("Refresher.Start did not exit within 2s of context cancel")
	}
}

// helper to silence unused-coordPub from a test that doesn't need it
func TestNew_DefaultsApplied(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := tokens.NewVerifierForTesting(pub)
	r, err := New(Options{
		CoordURL:    "http://example.test",
		APIKey:      "k",
		CoordPubKey: pub,
		Verifier:    v,
		// Interval and HTTPClient unset — defaults should apply
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if r.opts.Interval != DefaultInterval {
		t.Errorf("Interval = %v, want default %v", r.opts.Interval, DefaultInterval)
	}
	if r.client == nil {
		t.Error("client unset after defaults applied")
	}
}

func init() {
	// Tests rely on httptest.NewServer doing local-only network IO; if
	// the runtime is jailed or networking is disabled, fail fast with a
	// clear message rather than masquerading as test logic failures.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
}
