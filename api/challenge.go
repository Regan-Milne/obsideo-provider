package api

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

const (
	proofVersionV1        = 2
	proofVersionV1Replica = 3
)

// auditChallenge is the canonical request shape from the coord challenger.
// Mirrors coordinator/proof/types.go::AuditChallenge.
type auditChallenge struct {
	Version      int    `json:"version"`
	ChallengeID  string `json:"challenge_id"`
	MerkleRoot   string `json:"merkle_root"`
	ProviderID   string `json:"provider_id,omitempty"`
	ChunkIndex   int    `json:"chunk_index"`
	Nonce        string `json:"nonce"`
	ExpiresAt    int64  `json:"expires_at"`
	ProofVersion int    `json:"proof_version,omitempty"`
}

// auditResponse is the canonical response shape the coord verifier expects.
// Mirrors coordinator/proof/types.go::AuditResponse. The verifier checks
// challenge_id, nonce, merkle_root, chunk_index, chunk_data, merkle_proof.
// The other fields are echoed for parity but not validated.
type auditResponse struct {
	Version         int         `json:"version"`
	ChallengeID     string      `json:"challenge_id"`
	ProviderID      string      `json:"provider_id"`
	MerkleRoot      string      `json:"merkle_root"`
	ChunkIndex      int         `json:"chunk_index"`
	ChunkData       string      `json:"chunk_data"`
	MerkleProof     merkleProof `json:"merkle_proof"`
	TotalChunkCount int         `json:"total_chunk_count"`
	Nonce           string      `json:"nonce"`
	Timestamp       int64       `json:"timestamp"`
	ProofVersion    int         `json:"proof_version"`
}

type merkleProof struct {
	Siblings []string `json:"siblings"`
	Index    int      `json:"index"`
}

// handleChallenge answers a coord-issued audit challenge by reading the
// challenged chunk's bytes from disk and returning them along with the
// merkle proof from leaf to root. Replica mode (proof_version=3) is not
// supported in this handler — coord falls back to V1 raw mode when no
// ReplicaCommitment exists, and provider-clean does not register a
// /replica-commitment endpoint, so V1 raw is the only path that fires.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var ch auditChallenge
	if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}

	if ch.ProviderID != "" && s.providerID != "" && ch.ProviderID != s.providerID {
		writeError(w, http.StatusForbidden, "provider_id mismatch")
		return
	}
	if ch.ExpiresAt > 0 && time.Now().Unix() > ch.ExpiresAt {
		writeError(w, http.StatusGone, "challenge expired")
		return
	}
	if ch.MerkleRoot == "" {
		writeError(w, http.StatusBadRequest, "merkle_root required")
		return
	}
	if _, err := hex.DecodeString(ch.MerkleRoot); err != nil {
		writeError(w, http.StatusBadRequest, "invalid merkle_root hex")
		return
	}
	if ch.ProofVersion != 0 && ch.ProofVersion != proofVersionV1 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported proof_version %d (only V1 raw is implemented)", ch.ProofVersion))
		return
	}

	idx, err := s.store.GetIndex(ch.MerkleRoot)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "object not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "read index: "+err.Error())
		return
	}
	if idx.TotalChunks == 0 {
		writeError(w, http.StatusBadRequest, "object is empty")
		return
	}
	if ch.ChunkIndex < 0 || ch.ChunkIndex >= idx.TotalChunks {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("chunk_index %d out of range [0, %d)", ch.ChunkIndex, idx.TotalChunks))
		return
	}

	// Read just the challenged chunk's bytes from disk. Coord's verifier
	// recomputes chunkHashV1(idx, bytes) and compares to its stored hash;
	// a partial read would silently produce a wrong hash.
	f, err := s.store.OpenObject(ch.MerkleRoot)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "object not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "open object: "+err.Error())
		return
	}
	defer f.Close()

	offset := int64(ch.ChunkIndex) * int64(idx.ChunkSize)
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		writeError(w, http.StatusInternalServerError, "seek: "+err.Error())
		return
	}
	chunkBuf := make([]byte, idx.ChunkSize)
	n, rerr := io.ReadFull(f, chunkBuf)
	if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
		writeError(w, http.StatusInternalServerError, "read chunk: "+rerr.Error())
		return
	}
	chunkBuf = chunkBuf[:n]
	if len(chunkBuf) == 0 {
		writeError(w, http.StatusInternalServerError, "challenged chunk read empty")
		return
	}

	// Build merkle leaves from the precomputed chunk hashes. Each leaf is
	// sha3-512(chunkHash) per the SDK + coord's wealdtech-compatible tree.
	leaves := make([][]byte, idx.TotalChunks)
	for i, hexHash := range idx.ChunkHashes {
		raw, err := hex.DecodeString(hexHash)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("decode chunk_hash[%d]: %v", i, err))
			return
		}
		leaves[i] = sha3Sum512(raw)
	}
	siblings := computeMerkleProof(leaves, ch.ChunkIndex)

	writeJSON(w, http.StatusOK, auditResponse{
		Version:         ch.Version,
		ChallengeID:     ch.ChallengeID,
		ProviderID:      s.providerID,
		MerkleRoot:      ch.MerkleRoot,
		ChunkIndex:      ch.ChunkIndex,
		ChunkData:       base64.StdEncoding.EncodeToString(chunkBuf),
		MerkleProof:     merkleProof{Siblings: siblings, Index: ch.ChunkIndex},
		TotalChunkCount: idx.TotalChunks,
		Nonce:           ch.Nonce,
		Timestamp:       time.Now().Unix(),
		ProofVersion:    proofVersionV1,
	})
}
