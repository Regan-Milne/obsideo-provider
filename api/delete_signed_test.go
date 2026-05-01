package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// Tests for the user-signed delete endpoint (D4). Spec:
// docs/retention_authority_design.md §6.3 and §12 (invariants).

// deleteTestEnv wires a fresh Server with a Store and an ed25519 keypair
// the test controls. Returns the server, the private key for signing, and
// the obk_sig_<...> fingerprint to write to the ownership file.
func deleteTestEnv(t *testing.T) (*Server, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigFingerprint := "obk_sig_" + base64.RawURLEncoding.EncodeToString(pub)

	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil, nil, "") // verifier + pause nil; delete-signed uses neither
	return srv, priv, sigFingerprint
}

// seedOwnership puts a minimal object + ownership record. Returns the
// merkle so tests can delete against it.
func seedOwnership(t *testing.T, srv *Server, sigFingerprint string) string {
	t.Helper()
	merkle := strings.Repeat("f", 64)
	if err := srv.store.Put(merkle, []byte("payload-bytes"), store.DefaultChunkSize); err != nil {
		t.Fatal(err)
	}
	own := store.Ownership{
		OwnerPubkey:    "obk_pub_" + strings.Repeat("P", 43),
		OwnerSigPubkey: sigFingerprint,
		ReceivedAt:     time.Now().UTC(),
	}
	if err := srv.store.PutOwnership(merkle, own); err != nil {
		t.Fatal(err)
	}
	return merkle
}

// canonicalizeDeletePayload produces the same canonical JSON the SDK
// does. Duplicated here to keep the test independent of the SDK; any
// drift between the two implementations is a real interoperability bug
// and should fail a test rather than silently match.
func canonicalizeDeletePayload(accountID, merkleRoot, issuedAt, nonce string) string {
	// Sorted keys: account_id, issued_at, merkle_root, nonce.
	parts := []string{
		`"account_id":` + strconvQuote(accountID),
		`"issued_at":` + strconvQuote(issuedAt),
		`"merkle_root":` + strconvQuote(merkleRoot),
		`"nonce":` + strconvQuote(nonce),
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// buildAndSignDeleteRequest returns the JSON body for POST /delete/{merkle}.
func buildAndSignDeleteRequest(priv ed25519.PrivateKey, accountID, merkleRoot, issuedAt, nonce string) []byte {
	payload := canonicalizeDeletePayload(accountID, merkleRoot, issuedAt, nonce)
	sig := ed25519.Sign(priv, []byte(payload))
	body := map[string]string{
		"payload":   payload,
		"signature": base64.RawURLEncoding.EncodeToString(sig),
	}
	buf, _ := json.Marshal(body)
	return buf
}

func deleteTo(t *testing.T, srv *Server, merkle string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/delete/"+merkle, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// ----- Invariant coverage -----

func TestDelete_HappyPath_SucceedsAndRemovesFiles(t *testing.T) {
	srv, priv, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	body := buildAndSignDeleteRequest(priv, "acct-test", merkle, time.Now().UTC().Format(time.RFC3339Nano), "nonce-1")
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	// After delete: no ownership, no object data.
	if srv.store.HasOwnership(merkle) {
		t.Errorf("ownership file persists after signed delete")
	}
	if _, err := srv.store.Get(merkle); err == nil {
		t.Errorf("object bytes persist after signed delete")
	}
}

func TestDelete_NoOwnershipFile_AutoReject(t *testing.T) {
	// Invariant 2 of §12: absence of ownership file is an automatic reject
	// with no legacy fallback. Applies to pre-Phase-1 uploads and
	// legacy-account uploads (v2.1 spec §9.2).
	srv, priv, _ := deleteTestEnv(t)
	merkle := strings.Repeat("a", 64)
	// No seed — ownership absent.
	body := buildAndSignDeleteRequest(priv, "acct", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n1")
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusNotFound {
		t.Errorf("no ownership: code=%d, want 404", rec.Code)
	}
}

func TestDelete_WrongKey_Rejected(t *testing.T) {
	srv, _, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// Sign with a DIFFERENT private key.
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := buildAndSignDeleteRequest(wrongPriv, "acct", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n1")
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong key: code=%d, want 401", rec.Code)
	}
	// Ownership unchanged.
	if !srv.store.HasOwnership(merkle) {
		t.Errorf("ownership was deleted despite 401")
	}
}

func TestDelete_TamperedPayload_Rejected(t *testing.T) {
	srv, priv, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// Build a valid signed request, then mutate the payload. Verify fails.
	goodPayload := canonicalizeDeletePayload("acct-A", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n1")
	sigBytes := ed25519.Sign(priv, []byte(goodPayload))
	tamperedPayload := strings.Replace(goodPayload, "acct-A", "acct-B", 1)
	body, _ := json.Marshal(map[string]string{
		"payload":   tamperedPayload,
		"signature": base64.RawURLEncoding.EncodeToString(sigBytes),
	})
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered payload: code=%d, want 401", rec.Code)
	}
}

func TestDelete_MerkleMismatch_URLvsPayload_Rejected(t *testing.T) {
	// A valid signature over a payload referencing merkle-A, sent to
	// the URL for merkle-B, is someone replaying at the wrong endpoint.
	srv, priv, sig := deleteTestEnv(t)
	urlMerkle := seedOwnership(t, srv, sig)
	payloadMerkle := strings.Repeat("9", 64)

	body := buildAndSignDeleteRequest(priv, "acct", payloadMerkle, time.Now().UTC().Format(time.RFC3339Nano), "n1")
	rec := deleteTo(t, srv, urlMerkle, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("merkle mismatch: code=%d, want 400", rec.Code)
	}
}

func TestDelete_IssuedAtInPast_Rejected(t *testing.T) {
	srv, priv, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// 10 minutes ago — outside the ±5 minute drift window.
	tooOld := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	body := buildAndSignDeleteRequest(priv, "acct", merkle, tooOld, "n1")
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("past issued_at: code=%d, want 401", rec.Code)
	}
}

func TestDelete_IssuedAtInFuture_Rejected(t *testing.T) {
	srv, priv, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// 10 minutes in the future.
	tooNew := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	body := buildAndSignDeleteRequest(priv, "acct", merkle, tooNew, "n1")
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("future issued_at: code=%d, want 401", rec.Code)
	}
}

func TestDelete_NonceReplay_Rejected(t *testing.T) {
	// Same nonce used twice: second call must fail even with a fresh
	// signature (different issued_at).
	srv, priv, sig := deleteTestEnv(t)

	// First delete on one merkle.
	merkleA := seedOwnership(t, srv, sig)
	bodyA := buildAndSignDeleteRequest(priv, "acct", merkleA, time.Now().UTC().Format(time.RFC3339Nano), "shared-nonce")
	recA := deleteTo(t, srv, merkleA, bodyA)
	if recA.Code != http.StatusOK {
		t.Fatalf("first delete: code=%d body=%s", recA.Code, recA.Body.String())
	}

	// Seed another merkle, try to reuse the nonce for its delete.
	merkleB := strings.Repeat("b", 64)
	if err := srv.store.Put(merkleB, []byte("x"), store.DefaultChunkSize); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.PutOwnership(merkleB, store.Ownership{
		OwnerPubkey:    "obk_pub_" + strings.Repeat("P", 43),
		OwnerSigPubkey: sig,
		ReceivedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	bodyB := buildAndSignDeleteRequest(priv, "acct", merkleB, time.Now().UTC().Format(time.RFC3339Nano), "shared-nonce")
	recB := deleteTo(t, srv, merkleB, bodyB)
	if recB.Code != http.StatusUnauthorized {
		t.Errorf("nonce replay: code=%d, want 401", recB.Code)
	}
	// Second merkle's data unchanged.
	if !srv.store.HasOwnership(merkleB) {
		t.Errorf("replay rejection should have left merkleB ownership intact")
	}
}

func TestDelete_MalformedJSON_Rejected(t *testing.T) {
	srv, _, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)
	rec := deleteTo(t, srv, merkle, []byte("{ not valid"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: code=%d, want 400", rec.Code)
	}
}

func TestDelete_MissingPayload_Rejected(t *testing.T) {
	srv, _, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// signature present, payload empty.
	body, _ := json.Marshal(map[string]string{
		"payload":   "",
		"signature": "AAAA",
	})
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty payload: code=%d, want 400", rec.Code)
	}
}

func TestDelete_BadBase64Signature_Rejected(t *testing.T) {
	srv, _, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	body, _ := json.Marshal(map[string]string{
		"payload":   canonicalizeDeletePayload("a", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n1"),
		"signature": "!!!not base64url!!!",
	})
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad base64: code=%d, want 400", rec.Code)
	}
}

func TestDelete_WrongSignatureLength_Rejected(t *testing.T) {
	srv, _, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// 32-byte "signature" — base64url-valid but wrong length.
	shortSig := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	body, _ := json.Marshal(map[string]string{
		"payload":   canonicalizeDeletePayload("a", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n1"),
		"signature": shortSig,
	})
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("32-byte sig: code=%d, want 400", rec.Code)
	}
}

func TestDelete_PayloadMissingField_Rejected(t *testing.T) {
	srv, priv, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	// Sign a payload missing `nonce`.
	partial := `{"account_id":"a","issued_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","merkle_root":"` + merkle + `"}`
	sigBytes := ed25519.Sign(priv, []byte(partial))
	body, _ := json.Marshal(map[string]string{
		"payload":   partial,
		"signature": base64.RawURLEncoding.EncodeToString(sigBytes),
	})
	rec := deleteTo(t, srv, merkle, body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing field: code=%d, want 400", rec.Code)
	}
}

func TestDelete_IdempotentAfterDeletion_AutoReject(t *testing.T) {
	// After a successful delete, the ownership file is gone. A retry of
	// the same (or any) signed command must auto-reject per the no-
	// ownership-file rule — this is the "invariant 2 auto-reject" from §12.
	srv, priv, sig := deleteTestEnv(t)
	merkle := seedOwnership(t, srv, sig)

	body := buildAndSignDeleteRequest(priv, "a", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n1")
	rec1 := deleteTo(t, srv, merkle, body)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first delete: %d", rec1.Code)
	}
	// Second delete against the same merkle: different nonce (avoid replay
	// path), but ownership is gone.
	body2 := buildAndSignDeleteRequest(priv, "a", merkle, time.Now().UTC().Format(time.RFC3339Nano), "n2")
	rec2 := deleteTo(t, srv, merkle, body2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("replay after deletion: code=%d, want 404 (no ownership)", rec2.Code)
	}
}
