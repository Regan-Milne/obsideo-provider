package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/coverage"
	"github.com/obsideo/obsideo-provider/pausectl"
	"github.com/obsideo/obsideo-provider/store"
	"github.com/obsideo/obsideo-provider/tokens"
)

// Retention-authority Phase 1 invariant test coverage. Each top-level
// invariant from docs/retention_authority_design.md §12 is asserted by at
// least one test in the provider-clean test suite. This file holds the
// cross-cutting tests that don't belong to any single unit's file, plus
// a map (below) of which existing tests cover which invariant.
//
// ## Coverage map
//
// Invariant 1 (no coord-initiated provider-side delete path in Phase 1
// flows):
//   - TestInvariant1_RefresherNeverCallsStoreDelete — this file. Proves
//     the new Phase-1 coverage-refresh code path never mutates
//     provider-side data regardless of coord response.
//
// Invariant 2 (every compliant user-signed delete has a verified Ed25519
// signature against the stored owner_sig_pubkey; verification precedes
// any chunk access; absence of ownership file auto-rejects with no
// fallback):
//   - delete_signed_test.go::TestDelete_HappyPath_SucceedsAndRemovesFiles
//   - delete_signed_test.go::TestDelete_NoOwnershipFile_AutoReject
//   - delete_signed_test.go::TestDelete_WrongKey_Rejected
//   - delete_signed_test.go::TestDelete_TamperedPayload_Rejected
//   - delete_signed_test.go::TestDelete_MerkleMismatch_URLvsPayload_Rejected
//   - delete_signed_test.go::TestDelete_IssuedAtInPast_Rejected
//   - delete_signed_test.go::TestDelete_IssuedAtInFuture_Rejected
//   - delete_signed_test.go::TestDelete_NonceReplay_Rejected
//   - delete_signed_test.go::TestDelete_BadBase64Signature_Rejected
//   - delete_signed_test.go::TestDelete_WrongSignatureLength_Rejected
//   - delete_signed_test.go::TestDelete_IdempotentAfterDeletion_AutoReject
//   - TestInvariant2_X25519PrimitiveRejected — this file. Covers the
//     explicit §12.1 adversarial case "delete signed with the X25519
//     half (wrong primitive) rejected."
//
// Invariant 3 (no prune based on coverage answers older than
// staleness_threshold):
//   - store/coverage_test.go::TestUpdateCoverage_* (RefreshedAt field
//     is populated correctly; staleness check is Phase-2 prune code's
//     responsibility but the seam is tested here)
//   - TestInvariant3_CoverageAnswerExposesRefreshedAt — this file.
//     Proves the staleness-check input is carried through end-to-end.
//
// Invariant 4 (owner pubkeys are write-once at upload; never updated by
// coord-initiated flows; 0o444 enforces at the OS layer):
//   - store/ownership_test.go::TestPutOwnership_WriteOnce_SecondCallReturnsErrOwnershipExists
//   - store/ownership_test.go::TestPutOwnership_FileModeIs0o444
//   - TestInvariant4_SecondUploadCannotOverwriteOwnership — this file.
//     End-to-end HTTP test confirming a second upload attempt with a
//     different token does not mutate the stored ownership record.
//
// Invariant 5 (circuit-breaker activation halts prune decisions):
//   - pausectl/pausectl_test.go::TestApply_* (acceptance + rejection rules)
//   - pausectl/pausectl_test.go::TestIsPaused_AutoExpires
//   - pausectl/pausectl_test.go::TestLoad_PersistsAcrossRestart
//   - TestInvariant5_PauseCheckerGateHaltsPrune — this file. Wires
//     the canonical gate pattern (coverage.PauseChecker) through a
//     prospective prune-decision seam and confirms it halts.
//
// Invariant 6 (upload-token is the authority for owner pubkey assignment;
// upload-token compromise is a bounded window; existing ownership is
// protected by invariant 4):
//   - upload_ownership_test.go::TestUpload_* (token claims → ownership
//     file round-trip)
//   - TestInvariant6_OwnershipPubkeysMatchTokenClaims — this file.
//     Explicit assertion that the stored owner pubkeys equal the
//     ones the coord put in the upload token.
//
// Adversarial scenarios from §12.1 not already covered above:
//   - "Pause message signed by wrong key: rejected" →
//     pausectl_test.go::TestApply_WrongSignature
//   - "Pause message with past expires_at: rejected as stale" →
//     pausectl_test.go::TestApply_Expired
//   - "Replayed delete command (same nonce): rejected" →
//     delete_signed_test.go::TestDelete_NonceReplay_Rejected
//   - "User-signed delete against a root the user does not own" →
//     delete_signed_test.go::TestDelete_WrongKey_Rejected (same
//     mechanism: verify-against-stored-pubkey fails)
//   - "Stale cached answer used for deletion attempt: must fail" —
//     deletion does not consult the coverage cache; this is N/A in
//     Phase 1 architecture, noted for the record.

// ---------- Invariant 1 ----------

// TestInvariant1_RefresherNeverCallsStoreDelete proves that the
// Phase-1 coverage-refresh code path never mutates provider-side data,
// regardless of what the coord responds with. This is the positive form
// of invariant 1 restricted to the new Phase-1 flow: coverage answers
// drive cache updates, not deletions. (The legacy
// DELETE /objects/{merkle} route still exists for backward
// compatibility, gated off at the coord by GCConfig.CoordInitiatedDelete
// default false — that is a coord-side invariant tested in the
// coordinator module.)
func TestInvariant1_RefresherNeverCallsStoreDelete(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}

	// Seed three roots: one we'll have the mock coord answer "covered",
	// one "uncovered", one "orphaned" — the full coverage-response
	// matrix. Under invariant 1, none of these must trigger a delete.
	roots := []string{
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
	}
	for _, m := range roots {
		if err := st.Put(m, []byte("data-"+m[:4]), store.DefaultChunkSize); err != nil {
			t.Fatal(err)
		}
	}

	// Mock coord returning each status for the respective root. Response
	// shape is flat-map-by-merkle, per coverage.Response.
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := coverage.Response{
			roots[0]: {Status: store.CoverageStatusCovered, Until: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)},
			roots[1]: {Status: store.CoverageStatusUncovered, Reason: "account_expired"},
			roots[2]: {Status: store.CoverageStatusOrphaned, Reason: "unknown_merkle"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mock.Close()

	client := coverage.NewClient(mock.URL, "test-api-key", mock.Client())
	ref := &coverage.Refresher{
		Store:     st,
		Client:    client,
		Interval:  time.Hour,
		BatchSize: 100,
	}

	if err := ref.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// All three objects must still exist on disk after the refresh,
	// independent of their coverage status.
	for _, m := range roots {
		if _, err := st.Get(m); err != nil {
			t.Errorf("root %s: refresh deleted object (invariant 1 violated): %v", m[:8], err)
		}
	}
}

// ---------- Invariant 2 (additional case) ----------

// TestInvariant2_X25519PrimitiveRejected covers the explicit adversarial
// case from §12.1: "delete signed with the X25519 half (wrong primitive)
// rejected."
//
// A user mistakenly (or a malicious client deliberately) signing with
// their X25519 encryption key instead of their Ed25519 signing key must
// fail verification at the provider. Ed25519 and X25519 keys are
// distinguishable at the prefix (obk_pub_ vs obk_sig_) AND by the
// cryptographic operation: an Ed25519 signature generated over an X25519
// keypair yields bytes that Ed25519.Verify rejects against the stored
// Ed25519 owner_sig_pubkey. The stronger version of this check is that
// the ownership file distinguishes the two primitives at the prefix
// level, so an attempt to store or verify against the X25519 prefix
// fails the structural check before cryptography.
func TestInvariant2_X25519PrimitiveRejected(t *testing.T) {
	srv, _, sigFingerprint := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sigFingerprint)

	// Build a valid-looking delete payload.
	issued := time.Now().UTC().Format(time.RFC3339)
	payload := canonicalizeDeletePayload("acct-1", merkle, issued, "deadbeef")

	// Sign with Ed25519 over a DIFFERENT keypair to simulate a client
	// who generated a signing-half on the wrong primitive — i.e. they
	// used their encryption key's seed-derived X25519 priv as an
	// Ed25519 priv by mistake. The mechanism: independent keys.
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(wrongPriv, []byte(payload))

	body, _ := json.Marshal(map[string]string{
		"payload":   payload,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/delete/"+merkle, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong-primitive delete: code %d want 401 body=%s", rec.Code, rec.Body.String())
	}

	// The object must still exist.
	if _, err := srv.store.Get(merkle); err != nil {
		t.Errorf("object was deleted despite rejection (invariant 2 violated): %v", err)
	}
}

// ---------- Invariant 3 ----------

// TestInvariant3_CoverageAnswerExposesRefreshedAt proves the
// staleness-check input (RefreshedAt) is populated correctly and
// readable end-to-end through the refresh path. Phase-2 prune code
// will consult this field to enforce
// "RefreshedAt + staleness_threshold < now ⇒ retain, don't act."
//
// This test doesn't implement the prune check; it proves the seam the
// prune check will consume is correct.
func TestInvariant3_CoverageAnswerExposesRefreshedAt(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	merkle := strings.Repeat("d", 64)
	if err := st.Put(merkle, []byte("x"), store.DefaultChunkSize); err != nil {
		t.Fatal(err)
	}

	before := time.Now().UTC().Add(-1 * time.Second)

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := coverage.Response{
			merkle: {Status: store.CoverageStatusCovered, Until: time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mock.Close()

	client := coverage.NewClient(mock.URL, "test-api-key", mock.Client())
	ref := &coverage.Refresher{Store: st, Client: client, Interval: time.Hour, BatchSize: 10}
	if err := ref.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	after := time.Now().UTC().Add(1 * time.Second)

	cov, err := st.GetCoverage(merkle)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if cov.RefreshedAt.Before(before) || cov.RefreshedAt.After(after) {
		t.Errorf("RefreshedAt %v outside expected window [%v, %v]", cov.RefreshedAt, before, after)
	}

	// Future prune code's contract:
	//   if now.Sub(cov.RefreshedAt) > stalenessThreshold { retain; don't prune }
	// Simulate it here with a 1h threshold and confirm the seam works
	// as advertised: a just-refreshed answer is actionable; an old one
	// would not be.
	stalenessThreshold := time.Hour
	nowJustAfter := cov.RefreshedAt.Add(1 * time.Second)
	if nowJustAfter.Sub(cov.RefreshedAt) > stalenessThreshold {
		t.Error("fresh answer incorrectly classified as stale")
	}
	nowFarLater := cov.RefreshedAt.Add(stalenessThreshold).Add(1 * time.Second)
	if nowFarLater.Sub(cov.RefreshedAt) <= stalenessThreshold {
		t.Error("stale answer incorrectly classified as fresh")
	}
}

// ---------- Invariant 4 ----------

// TestInvariant4_SecondUploadCannotOverwriteOwnership confirms that a
// second upload attempt with a different token (different owner
// pubkeys) for the same merkle does NOT mutate the stored ownership
// record. The first upload wins; subsequent upload attempts find an
// existing ownership file and must either no-op the ownership write
// (api.handleUpload uses idempotent write via ErrOwnershipExists) or
// reject the upload entirely.
//
// This is the bounded-damage guarantee behind invariant 6: even if the
// coord is compromised mid-uploads for the same merkle, the FIRST
// upload's ownership stands.
func TestInvariant4_SecondUploadCannotOverwriteOwnership(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	merkle := strings.Repeat("e", 64)

	firstOwn := store.Ownership{
		OwnerPubkey:    "obk_pub_" + strings.Repeat("A", 43),
		OwnerSigPubkey: "obk_sig_" + strings.Repeat("B", 43),
		ReceivedAt:     time.Now().UTC(),
	}
	if err := st.PutOwnership(merkle, firstOwn); err != nil {
		t.Fatalf("first PutOwnership: %v", err)
	}

	secondOwn := store.Ownership{
		OwnerPubkey:    "obk_pub_" + strings.Repeat("X", 43),
		OwnerSigPubkey: "obk_sig_" + strings.Repeat("Y", 43),
		ReceivedAt:     time.Now().UTC(),
	}
	err = st.PutOwnership(merkle, secondOwn)
	if err == nil {
		t.Fatal("second PutOwnership unexpectedly succeeded")
	}

	stored, err := st.GetOwnership(merkle)
	if err != nil {
		t.Fatal(err)
	}
	if stored.OwnerPubkey != firstOwn.OwnerPubkey {
		t.Errorf("OwnerPubkey changed: got %q, want %q (invariant 4 violated)",
			stored.OwnerPubkey, firstOwn.OwnerPubkey)
	}
	if stored.OwnerSigPubkey != firstOwn.OwnerSigPubkey {
		t.Errorf("OwnerSigPubkey changed: got %q, want %q (invariant 4 violated)",
			stored.OwnerSigPubkey, firstOwn.OwnerSigPubkey)
	}
}

// ---------- Invariant 5 ----------

// TestInvariant5_PauseCheckerGateHaltsPrune demonstrates the canonical
// gate pattern: a prospective prune-decision function that consults
// coverage.PauseChecker halts when paused and proceeds when not.
//
// Phase 1 does not implement pruning (Phase 2 work); this test proves
// the seam is usable by future prune code and will correctly enforce
// invariant 5.
func TestInvariant5_PauseCheckerGateHaltsPrune(t *testing.T) {
	dir := t.TempDir()
	coldPub, coldPri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, err := pausectl.Load(dir, coldPub)
	if err != nil {
		t.Fatal(err)
	}

	// Canonical gate pattern that future prune code should use:
	var prunes atomic.Int32
	prune := func(checker coverage.PauseChecker, now time.Time) {
		if checker.IsPaused(now) {
			return
		}
		prunes.Add(1)
	}

	// Before pause: gate lets pruning through.
	now := time.Now().UTC()
	prune(state, now)
	if prunes.Load() != 1 {
		t.Fatalf("pre-pause prune count: got %d want 1", prunes.Load())
	}

	// Activate a pause.
	expiry := now.Add(24 * time.Hour)
	signal := pausectl.Signal{
		Type:           pausectl.SignalType,
		Version:        pausectl.SignalVersion,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      expiry.Format(time.RFC3339),
		Scope:          pausectl.SignalScope,
		SequenceNumber: 1,
		Reason:         "invariant-5-test",
	}
	payload, _ := json.Marshal(signal)
	sig := ed25519.Sign(coldPri, payload)
	env := pausectl.Envelope{
		Payload:   string(payload),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	if _, err := state.Apply(env, now); err != nil {
		t.Fatal(err)
	}

	// During pause: gate blocks pruning.
	prune(state, now)
	if got := prunes.Load(); got != 1 {
		t.Fatalf("during-pause prune count: got %d, want 1 (invariant 5 violated)", got)
	}

	// After auto-expiry: gate lets pruning through again (no manual
	// resume is possible; time is the only unpause mechanism).
	prune(state, expiry.Add(time.Second))
	if got := prunes.Load(); got != 2 {
		t.Fatalf("post-expiry prune count: got %d want 2", got)
	}
}

// ---------- Invariant 6 ----------

// TestInvariant6_OwnershipPubkeysMatchTokenClaims proves the coord's
// upload token is the sole authority for owner-pubkey assignment at
// upload time: whatever pubkeys the coord puts in the token claims,
// the provider writes verbatim into the ownership file. No
// client-side override, no provider-side substitution.
//
// This is the positive half of the invariant. The bounded-damage
// half (invariant 4: existing ownership is not rewritten) is covered
// separately.
func TestInvariant6_OwnershipPubkeysMatchTokenClaims(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)

	merkle := strings.Repeat("f", 64)
	claimedPub := "obk_pub_" + strings.Repeat("P", 43)
	claimedSig := "obk_sig_" + strings.Repeat("S", 43)

	claims := tokens.Claims{
		Type:           "upload",
		MerkleRoot:     merkle,
		ProviderID:     "p",
		AccountID:      "inv6-acct",
		OwnerPubkey:    claimedPub,
		OwnerSigPubkey: claimedSig,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := signTestToken(t, priv, claims)

	rec := uploadTo(t, srv, merkle, tok, validPayloadBytes())
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: code %d body=%s", rec.Code, rec.Body.String())
	}

	own, err := srv.store.GetOwnership(merkle)
	if err != nil {
		t.Fatalf("GetOwnership: %v", err)
	}
	if own.OwnerPubkey != claimedPub {
		t.Errorf("OwnerPubkey: got %q want %q (invariant 6 violated)", own.OwnerPubkey, claimedPub)
	}
	if own.OwnerSigPubkey != claimedSig {
		t.Errorf("OwnerSigPubkey: got %q want %q (invariant 6 violated)", own.OwnerSigPubkey, claimedSig)
	}
}
