package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestProofSigPayload_Golden pins the EXACT canonical bytes. The coordinator
// reconstructs this same payload in a separate Go module to verify provider
// signatures; if either side's serialization drifts, signatures silently stop
// verifying across the fleet. This golden vector is the contract. Do NOT edit
// the expected string to make a code change pass — a change here is a
// wire-format break that must be intentional and mirrored on the coord side.
func TestProofSigPayload_Golden(t *testing.T) {
	chunk := []byte("the quick brown fox")
	digest := sha256.Sum256(chunk)

	got := string(ProofSigPayload(
		"prov-1111", // provider_id
		"chal-2222", // challenge_id
		"abcdef",    // nonce (hex)
		"deadbeef",  // merkle_root (hex)
		7,           // chunk_index
		0,           // block_index
		2,           // proof_version (V1 raw)
		chunk,
	))

	want := "obsideo-proof-response-v1\n" +
		"prov-1111\n" +
		"chal-2222\n" +
		"abcdef\n" +
		"deadbeef\n" +
		"7\n" +
		"0\n" +
		"2\n" +
		hex.EncodeToString(digest[:])

	if got != want {
		t.Fatalf("canonical payload drift:\n got: %q\nwant: %q", got, want)
	}
}

// TestProofSigPayload_BindsEveryField ensures no field is a no-op: changing
// any one of them must change the signed bytes, or a signature could be
// replayed across challenges/chunks/data.
func TestProofSigPayload_BindsEveryField(t *testing.T) {
	base := ProofSigPayload("p", "c", "n", "m", 1, 0, 2, []byte("x"))
	variants := map[string][]byte{
		"provider_id":   ProofSigPayload("P", "c", "n", "m", 1, 0, 2, []byte("x")),
		"challenge_id":  ProofSigPayload("p", "C", "n", "m", 1, 0, 2, []byte("x")),
		"nonce":         ProofSigPayload("p", "c", "N", "m", 1, 0, 2, []byte("x")),
		"merkle_root":   ProofSigPayload("p", "c", "n", "M", 1, 0, 2, []byte("x")),
		"chunk_index":   ProofSigPayload("p", "c", "n", "m", 2, 0, 2, []byte("x")),
		"block_index":   ProofSigPayload("p", "c", "n", "m", 1, 1, 2, []byte("x")),
		"proof_version": ProofSigPayload("p", "c", "n", "m", 1, 0, 4, []byte("x")),
		"chunk_data":    ProofSigPayload("p", "c", "n", "m", 1, 0, 2, []byte("y")),
	}
	for field, v := range variants {
		if string(v) == string(base) {
			t.Fatalf("changing %s did not change the signed payload", field)
		}
	}
}
