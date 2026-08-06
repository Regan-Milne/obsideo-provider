package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/identity"
	"github.com/obsideo/obsideo-provider/store"
)

// signedTestEnv stands up a server with a real signing identity and one
// stored object, returning everything a "third-party verifier" needs.
func signedTestEnv(t *testing.T) (*Server, *identity.Identity, string, *store.Store) {
	t.Helper()
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	merkle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	data := bytes.Repeat([]byte("a"), (2*store.DefaultChunkSize)+17)
	if err := st.Put(merkle, data, store.DefaultChunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}
	ident, err := identity.LoadOrCreate(tempDir)
	if err != nil {
		t.Fatalf("identity.LoadOrCreate: %v", err)
	}
	server := New(st, nil, nil, "test-provider-id", true)
	server.SetProofSigner(ident)
	return server, ident, merkle, st
}

func issueChallenge(t *testing.T, server *Server, merkle string, proofVersion int) auditResponse {
	t.Helper()
	body, _ := json.Marshal(auditChallenge{
		Version:      proofVersion,
		ChallengeID:  "ch-signed-1",
		MerkleRoot:   merkle,
		ProviderID:   "test-provider-id",
		ChunkIndex:   1,
		Nonce:        "deadbeef",
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
		ProofVersion: proofVersion,
	})
	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	res := httptest.NewRecorder()
	server.handleChallenge(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", res.Code, res.Body.String())
	}
	var got auditResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return got
}

// verifyResponseSig does exactly what a third-party verifier (coordinator or
// customer SDK) will do: reconstruct the canonical payload from the response
// fields + the RAW decoded bytes, then ed25519.Verify against the provider's
// REGISTERED public key (never a key the response itself supplies).
func verifyResponseSig(t *testing.T, resp auditResponse, blockIndex int, pub ed25519.PublicKey) bool {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(resp.ChunkData)
	if err != nil {
		t.Fatalf("decode chunk_data: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	payload := identity.ProofSigPayload(
		resp.ProviderID, resp.ChallengeID, resp.Nonce, resp.MerkleRoot,
		resp.ChunkIndex, blockIndex, resp.ProofVersion, raw,
	)
	return ed25519.Verify(pub, payload, sig)
}

// TestSignedChallengeResponse_V1Raw is the core loop: challenge → signed
// response → independent verification with no trust in the server.
func TestSignedChallengeResponse_V1Raw(t *testing.T) {
	server, ident, merkle, _ := signedTestEnv(t)
	resp := issueChallenge(t, server, merkle, proofVersionV1)

	if resp.Signature == "" || resp.KeyID == "" {
		t.Fatal("signed server emitted no signature/key_id")
	}
	if resp.KeyID != ident.KeyID() {
		t.Fatalf("key_id = %q, want %q", resp.KeyID, ident.KeyID())
	}
	if !verifyResponseSig(t, resp, 0, ident.PublicKey()) {
		t.Fatal("signature did not verify against the provider's registered public key")
	}
}

// TestSignedChallengeResponse_V4Compact — same loop for compact proofs,
// which is what the production challenger issues ~78% of the time. The
// signature binds the compact BLOCK bytes and the block index.
func TestSignedChallengeResponse_V4Compact(t *testing.T) {
	server, ident, merkle, _ := signedTestEnv(t)
	resp := issueChallenge(t, server, merkle, proofVersionCompact)

	if resp.Signature == "" {
		t.Fatal("compact response unsigned")
	}
	if !verifyResponseSig(t, resp, resp.MerkleProof.Index, ident.PublicKey()) {
		t.Fatal("compact signature did not verify")
	}
}

// TestSignedChallengeResponse_TamperFails — flipping any response field or
// the data itself must break verification. This is the negative case that
// makes a signed proof evidence rather than decoration.
func TestSignedChallengeResponse_TamperFails(t *testing.T) {
	server, ident, merkle, _ := signedTestEnv(t)
	resp := issueChallenge(t, server, merkle, proofVersionV1)

	tampered := resp
	raw, _ := base64.StdEncoding.DecodeString(resp.ChunkData)
	raw[0] ^= 0xFF
	tampered.ChunkData = base64.StdEncoding.EncodeToString(raw)
	if verifyResponseSig(t, tampered, 0, ident.PublicKey()) {
		t.Fatal("tampered chunk_data verified — signature does not bind the data")
	}

	tampered = resp
	tampered.Nonce = "beefdead"
	if verifyResponseSig(t, tampered, 0, ident.PublicKey()) {
		t.Fatal("altered nonce verified — signature does not bind the challenge")
	}

	tampered = resp
	tampered.ChunkIndex = 0
	if verifyResponseSig(t, tampered, 0, ident.PublicKey()) {
		t.Fatal("altered chunk_index verified — signature does not bind the chunk")
	}
}

// TestSignedChallengeResponse_WrongKeyFails — a signature must not verify
// against any key but the signer's. This is what stops provider A's proofs
// standing in for provider B.
func TestSignedChallengeResponse_WrongKeyFails(t *testing.T) {
	server, _, merkle, _ := signedTestEnv(t)
	resp := issueChallenge(t, server, merkle, proofVersionV1)

	other, err := identity.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if verifyResponseSig(t, resp, 0, other.PublicKey()) {
		t.Fatal("signature verified against a different provider's key")
	}
}

// TestUnsignedServerBackwardCompatible — a server with no signer must emit
// the pre-signing wire format: no signature, no key_id, everything else
// unchanged. This is the mixed-fleet guarantee for the rollout window.
func TestUnsignedServerBackwardCompatible(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	merkle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := st.Put(merkle, bytes.Repeat([]byte("a"), store.DefaultChunkSize+5), store.DefaultChunkSize); err != nil {
		t.Fatal(err)
	}
	server := New(st, nil, nil, "test-provider-id", true) // no SetProofSigner

	body, _ := json.Marshal(auditChallenge{
		Version: proofVersionV1, ChallengeID: "ch-legacy", MerkleRoot: merkle,
		ChunkIndex: 0, Nonce: "deadbeef",
		ExpiresAt: time.Now().Add(time.Minute).Unix(), ProofVersion: proofVersionV1,
	})
	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	res := httptest.NewRecorder()
	server.handleChallenge(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d", res.Code)
	}
	var rawResp map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &rawResp); err != nil {
		t.Fatal(err)
	}
	if _, present := rawResp["signature"]; present {
		t.Fatal("unsigned server emitted a signature field")
	}
	if _, present := rawResp["key_id"]; present {
		t.Fatal("unsigned server emitted a key_id field")
	}
}
