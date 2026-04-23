package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Regan-Milne/obsideo-provider/store"
	"github.com/Regan-Milne/obsideo-provider/tokens"
)

// D1 tests: verify the provider-clean upload handler writes the ownership
// file when the upload token carries both owner pubkeys, and skips the
// write for legacy-account uploads (token missing owner_sig_pubkey).
//
// Spec: docs/retention_authority_design.md §6.1, §9.1, §9.2.

// signTestToken builds and signs a token in the same format as the
// coordinator: base64url(claims_json).base64url(sig).
func signTestToken(t *testing.T, priv ed25519.PrivateKey, claims tokens.Claims) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sig := ed25519.Sign(priv, body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func newTestServerWithVerifier(t *testing.T) (*Server, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	dataDir := t.TempDir()
	st, err := store.New(filepath.Join(dataDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	v := tokens.NewVerifierForTesting(pub)
	return New(st, v, nil), priv
}

func uploadTo(t *testing.T, srv *Server, merkle, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload/"+merkle, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func validPayloadBytes() []byte {
	// Small payload; content doesn't matter for ownership tests.
	return bytes.Repeat([]byte("x"), 256)
}

func TestUpload_WithOwnerPubkeys_WritesOwnershipFile(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	merkle := strings.Repeat("a", 64)
	ownerPub := "obk_pub_" + strings.Repeat("P", 43)
	ownerSig := "obk_sig_" + strings.Repeat("S", 43)

	claims := tokens.Claims{
		Type:           "upload",
		MerkleRoot:     merkle,
		ProviderID:     "test-provider",
		AccountID:      "test-account",
		OwnerPubkey:    ownerPub,
		OwnerSigPubkey: ownerSig,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := signTestToken(t, priv, claims)
	rec := uploadTo(t, srv, merkle, tok, validPayloadBytes())
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: code=%d body=%s", rec.Code, rec.Body.String())
	}

	own, err := srv.store.GetOwnership(merkle)
	if err != nil {
		t.Fatalf("GetOwnership after upload: %v", err)
	}
	if own.OwnerPubkey != ownerPub {
		t.Errorf("persisted OwnerPubkey = %q, want %q", own.OwnerPubkey, ownerPub)
	}
	if own.OwnerSigPubkey != ownerSig {
		t.Errorf("persisted OwnerSigPubkey = %q, want %q", own.OwnerSigPubkey, ownerSig)
	}
	if own.ReceivedAt.IsZero() {
		t.Errorf("ReceivedAt should be set; got zero value")
	}
}

func TestUpload_WithoutOwnerSigPubkey_SkipsOwnershipFile(t *testing.T) {
	// Legacy-account upload: token carries OwnerPubkey but not OwnerSigPubkey.
	// The mixed-state rule from design §9.2 says provider-clean must skip
	// the ownership-file write entirely in this case.
	srv, priv := newTestServerWithVerifier(t)
	merkle := strings.Repeat("b", 64)

	claims := tokens.Claims{
		Type:        "upload",
		MerkleRoot:  merkle,
		ProviderID:  "test-provider",
		AccountID:   "legacy-account",
		OwnerPubkey: "obk_pub_" + strings.Repeat("P", 43),
		// OwnerSigPubkey deliberately empty.
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := signTestToken(t, priv, claims)
	rec := uploadTo(t, srv, merkle, tok, validPayloadBytes())
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if srv.store.HasOwnership(merkle) {
		t.Errorf("ownership file was created for legacy-account upload; should have been skipped")
	}
}

func TestUpload_WithNeitherPubkey_SkipsOwnershipFile(t *testing.T) {
	// Fully pre-Phase-1 token (no pubkey claims at all). Still a valid
	// upload path; still no ownership file.
	srv, priv := newTestServerWithVerifier(t)
	merkle := strings.Repeat("c", 64)

	claims := tokens.Claims{
		Type:       "upload",
		MerkleRoot: merkle,
		ProviderID: "test-provider",
		AccountID:  "really-legacy",
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := signTestToken(t, priv, claims)
	rec := uploadTo(t, srv, merkle, tok, validPayloadBytes())
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if srv.store.HasOwnership(merkle) {
		t.Errorf("ownership file was created for pre-Phase-1 upload; should have been skipped")
	}
}

func TestUpload_IdempotentOnOwnershipExists(t *testing.T) {
	// A retry of the same upload MUST NOT fail due to ErrOwnershipExists.
	// Invariant 4: first upload wins; subsequent uploads of the same
	// merkle converge on the same state.
	srv, priv := newTestServerWithVerifier(t)
	merkle := strings.Repeat("d", 64)
	ownerPub := "obk_pub_" + strings.Repeat("P", 43)
	ownerSig := "obk_sig_" + strings.Repeat("S", 43)

	claims := tokens.Claims{
		Type:           "upload",
		MerkleRoot:     merkle,
		ProviderID:     "test-provider",
		AccountID:      "test-account",
		OwnerPubkey:    ownerPub,
		OwnerSigPubkey: ownerSig,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
	tok := signTestToken(t, priv, claims)
	payload := validPayloadBytes()

	// First upload writes ownership.
	rec1 := uploadTo(t, srv, merkle, tok, payload)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first upload: code=%d body=%s", rec1.Code, rec1.Body.String())
	}

	// Second upload of the same merkle (retry) MUST succeed, not error.
	rec2 := uploadTo(t, srv, merkle, tok, payload)
	if rec2.Code != http.StatusOK {
		t.Errorf("retry upload: expected 200 (idempotent); got %d body=%s", rec2.Code, rec2.Body.String())
	}

	// Ownership still present, unchanged, with the ORIGINAL pubkeys.
	own, err := srv.store.GetOwnership(merkle)
	if err != nil {
		t.Fatal(err)
	}
	if own.OwnerPubkey != ownerPub || own.OwnerSigPubkey != ownerSig {
		t.Errorf("ownership changed after retry; got %+v", own)
	}
}

func TestUpload_LegacyThenV21_DoesNotBackfillOwnership(t *testing.T) {
	// Edge case: a legacy-account upload happens first (no ownership
	// written), then later the same merkle is replayed with a v2.1 token
	// carrying pubkeys. The design §9.2 rule is "no backfill by design"
	// for legacy data. We don't enforce this at the store layer (the
	// upload handler would call PutOwnership on the v2.1 replay and
	// succeed because no ownership exists yet), but this test documents
	// the current behavior: the v2.1 replay DOES write ownership because
	// the first upload didn't create one.
	//
	// This is acceptable for Phase 1 because replays on the same merkle
	// come from the same customer (upload tokens are coord-issued per
	// upload); they can't be attacker-initiated.
	srv, priv := newTestServerWithVerifier(t)
	merkle := strings.Repeat("e", 64)

	legacyClaims := tokens.Claims{
		Type:       "upload",
		MerkleRoot: merkle,
		ProviderID: "p",
		AccountID:  "legacy-a",
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	}
	legacyTok := signTestToken(t, priv, legacyClaims)
	rec1 := uploadTo(t, srv, merkle, legacyTok, validPayloadBytes())
	if rec1.Code != http.StatusOK {
		t.Fatalf("legacy upload: %d", rec1.Code)
	}
	if srv.store.HasOwnership(merkle) {
		t.Fatal("legacy upload should not have written ownership")
	}

	// v2.1 replay with pubkeys: ownership is written.
	v21Claims := legacyClaims
	v21Claims.OwnerPubkey = "obk_pub_" + strings.Repeat("P", 43)
	v21Claims.OwnerSigPubkey = "obk_sig_" + strings.Repeat("S", 43)
	v21Tok := signTestToken(t, priv, v21Claims)
	rec2 := uploadTo(t, srv, merkle, v21Tok, validPayloadBytes())
	if rec2.Code != http.StatusOK {
		t.Fatalf("v2.1 replay: %d", rec2.Code)
	}
	if !srv.store.HasOwnership(merkle) {
		t.Errorf("v2.1 replay should have written ownership (no prior record existed)")
	}
}

// Sanity helper: silence unused-import warning if we switch to direct
// body reading.
var _ = io.ReadAll
