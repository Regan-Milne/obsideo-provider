package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/store"
	"golang.org/x/crypto/sha3"
)

// walkSubChunkProof recomputes the seal from a leaf + its sibling path, exactly
// as coordinator/proof.walkMerkleProof (and the coord verifier) does: SHA3-512
// pair hashing, current-is-left when the running index is even. Used to close
// the v4 HTTP round-trip: the handler's response must walk back to the seal the
// provider would independently build from the chunk bytes.
func walkSubChunkProof(t *testing.T, leaf []byte, siblings []string, index int) []byte {
	t.Helper()
	current := leaf
	idx := index
	for i, sh := range siblings {
		sib, err := hex.DecodeString(sh)
		if err != nil {
			t.Fatalf("decode sibling %d: %v", i, err)
		}
		h := sha3.New512()
		if idx%2 == 0 {
			h.Write(current)
			h.Write(sib)
		} else {
			h.Write(sib)
			h.Write(current)
		}
		current = h.Sum(nil)
		idx /= 2
	}
	return current
}

// TestHandleChallengeV4RoundTrip drives a proof_version=4 challenge through the
// real HTTP handler for both a full multi-block chunk and a chunk whose final
// block is short, and asserts the response block bytes + merkle proof
// reconstruct the sub-chunk seal the provider builds from the same bytes.
func TestHandleChallengeV4RoundTrip(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	// chunkSize = 4 blocks. Object spans 2 chunks:
	//   chunk 0: 16384 bytes -> 4 full 4096-byte blocks.
	//   chunk 1:  5000 bytes -> 2 blocks, final block short (904 bytes).
	const chunkSize = 4 * subChunkBlockSize // 16384
	data := goldenChunk(chunkSize + 5000)
	merkle := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := st.Put(merkle, data, chunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}
	idx, err := st.GetIndex(merkle)
	if err != nil {
		t.Fatalf("GetIndex: %v", err)
	}
	if idx.TotalChunks != 2 {
		t.Fatalf("expected 2 chunks, got %d", idx.TotalChunks)
	}

	server := New(st, nil, nil, "test-provider-id", true)

	cases := []struct {
		name       string
		chunkIndex int
		blockIndex int
		chunkBytes []byte
		wantLen    int
	}{
		{
			name:       "full_block",
			chunkIndex: 0,
			blockIndex: 2,
			chunkBytes: data[:chunkSize],
			wantLen:    subChunkBlockSize,
		},
		{
			name:       "short_final_block",
			chunkIndex: 1,
			blockIndex: 1,
			chunkBytes: data[chunkSize:],
			wantLen:    5000 - subChunkBlockSize, // 904
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(auditChallenge{
				Version:      proofVersionCompact,
				ChallengeID:  "ch-v4",
				MerkleRoot:   merkle,
				ProviderID:   "test-provider-id",
				ChunkIndex:   tc.chunkIndex,
				BlockIndex:   tc.blockIndex,
				Nonce:        "cafebabe",
				ExpiresAt:    time.Now().Add(time.Minute).Unix(),
				ProofVersion: proofVersionCompact,
			})
			req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
			res := httptest.NewRecorder()
			server.handleChallenge(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
			}

			var got auditResponse
			if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// Echoes: proof_version 4, chunk_index, nonce, and the merkle proof
			// index carries the block_index per the v4 contract.
			if got.ProofVersion != proofVersionCompact {
				t.Errorf("proof_version echo = %d, want %d", got.ProofVersion, proofVersionCompact)
			}
			if got.ChunkIndex != tc.chunkIndex {
				t.Errorf("chunk_index echo = %d, want %d", got.ChunkIndex, tc.chunkIndex)
			}
			if got.Nonce != "cafebabe" {
				t.Errorf("nonce echo = %q, want %q", got.Nonce, "cafebabe")
			}
			if got.MerkleProof.Index != tc.blockIndex {
				t.Errorf("merkle_proof.index = %d, want block_index %d", got.MerkleProof.Index, tc.blockIndex)
			}

			// chunk_data must be exactly the challenged block's raw bytes.
			block, err := base64.StdEncoding.DecodeString(got.ChunkData)
			if err != nil {
				t.Fatalf("chunk_data base64: %v", err)
			}
			if len(block) != tc.wantLen {
				t.Errorf("block len = %d, want %d", len(block), tc.wantLen)
			}
			wantBlock := tc.chunkBytes[tc.blockIndex*subChunkBlockSize : tc.blockIndex*subChunkBlockSize+tc.wantLen]
			if !bytes.Equal(block, wantBlock) {
				t.Errorf("block bytes mismatch at chunk %d block %d", tc.chunkIndex, tc.blockIndex)
			}

			// The proof must walk back to the seal the provider builds from the
			// full chunk bytes — the cross-side verify the coordinator performs.
			wantSeal, err := buildSubChunkSeal(tc.chunkBytes)
			if err != nil {
				t.Fatalf("buildSubChunkSeal: %v", err)
			}
			leaf := subChunkLeaf(tc.blockIndex, block)
			gotRoot := hex.EncodeToString(walkSubChunkProof(t, leaf, got.MerkleProof.Siblings, got.MerkleProof.Index))
			if gotRoot != wantSeal {
				t.Errorf("proof does not reconstruct seal:\n got %s\nwant %s", gotRoot, wantSeal)
			}
		})
	}
}

// TestHandleChallengeV4BlockIndexOutOfRange: a block_index past the chunk's
// block count is a 400, same error style as chunk_index-out-of-range.
func TestHandleChallengeV4BlockIndexOutOfRange(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	// Single chunk of 5000 bytes -> 2 blocks; block_index 2 is out of range.
	merkle := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	data := goldenChunk(5000)
	if err := st.Put(merkle, data, store.DefaultChunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}
	server := New(st, nil, nil, "", true)

	body, _ := json.Marshal(auditChallenge{
		Version:      proofVersionCompact,
		ChallengeID:  "ch-oor",
		MerkleRoot:   merkle,
		ChunkIndex:   0,
		BlockIndex:   2,
		Nonce:        "00",
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
		ProofVersion: proofVersionCompact,
	})
	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	res := httptest.NewRecorder()
	server.handleChallenge(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", res.Code, res.Body.String())
	}

	var errBody map[string]string
	if err := json.Unmarshal(res.Body.Bytes(), &errBody); err != nil {
		t.Fatalf("unmarshal error body: %v", err)
	}
	if want := "block_index 2 out of range [0, 2)"; errBody["error"] != want {
		t.Errorf("error = %q, want %q", errBody["error"], want)
	}
}

// TestHandleChallengeUnknownProofVersion: any proof_version outside the handled
// set {0, 2, 4} is still an explicit 400 (unchanged legacy behavior).
func TestHandleChallengeUnknownProofVersion(t *testing.T) {
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	merkle := "beef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"
	if err := st.Put(merkle, goldenChunk(4096), store.DefaultChunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}
	server := New(st, nil, nil, "", true)

	for _, ver := range []int{3, 5, 99} {
		body, _ := json.Marshal(auditChallenge{
			ChallengeID:  "ch-bad-ver",
			MerkleRoot:   merkle,
			ChunkIndex:   0,
			Nonce:        "00",
			ExpiresAt:    time.Now().Add(time.Minute).Unix(),
			ProofVersion: ver,
		})
		req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
		res := httptest.NewRecorder()
		server.handleChallenge(res, req)
		if res.Code != http.StatusBadRequest {
			t.Errorf("proof_version %d: status = %d, want 400", ver, res.Code)
		}
	}
}
