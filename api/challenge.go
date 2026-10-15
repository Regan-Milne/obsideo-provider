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

	"github.com/obsideo/obsideo-provider/identity"
	"github.com/obsideo/obsideo-provider/store"
)

const (
	proofVersionV1        = 2
	proofVersionV1Replica = 3
	proofVersionCompact   = 4 // compact proofs: challenge is over a 4096-byte block within the chunk
)

// auditChallenge is the request shape a challenger sends.
type auditChallenge struct {
	Version      int    `json:"version"`
	ChallengeID  string `json:"challenge_id"`
	MerkleRoot   string `json:"merkle_root"`
	ProviderID   string `json:"provider_id,omitempty"`
	ChunkIndex   int    `json:"chunk_index"`
	BlockIndex   int    `json:"block_index"` // compact proofs (v4): which 4096-byte block of the chunk; 0 for v1/v2
	Nonce        string `json:"nonce"`
	ExpiresAt    int64  `json:"expires_at"`
	ProofVersion int    `json:"proof_version,omitempty"`
}

// auditResponse is the response shape a verifier expects.
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

	// Signature is the provider's Ed25519 signature (base64 std) over the
	// canonical proof payload (identity.ProofSigPayload). KeyID tags which
	// provider key signed. Both omitempty: a provider with no signing
	// identity emits neither field, and the response is byte-identical to
	// pre-signing wire format, so mixed fleets interoperate.
	Signature string `json:"signature,omitempty"`
	KeyID     string `json:"key_id,omitempty"`
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
//
// Authenticated by a coordinator-signed audit token; see challenge_auth.go.
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var ch auditChallenge
	// A challenge body is a few hundred bytes; cap it so the route cannot be
	// used to make the provider buffer arbitrary input before auth is checked.
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxChallengeBody)).Decode(&ch); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if status, msg := s.authorizeChallenge(r, ch); status != 0 {
		writeError(w, status, msg)
		return
	}
	s.serveChallenge(w, ch)
}

const maxChallengeBody = 64 << 10

// serveChallenge is the shared challenge core: validates the challenge,
// reads the chunk, builds the proof (V1 raw or V4 compact), signs, responds.
// Called by handleChallenge (coord path, audit-token-authenticated; see
// challenge_auth.go) and handleClientChallenge (customer path,
// token-authenticated + rate-limited). Callers authorize; this does not.
func (s *Server) serveChallenge(w http.ResponseWriter, ch auditChallenge) {
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
	if ch.ProofVersion != 0 && ch.ProofVersion != proofVersionV1 && ch.ProofVersion != proofVersionCompact {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported proof_version %d (only V1 raw and V4 compact are implemented)", ch.ProofVersion))
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

	// Read just the challenged chunk's bytes from disk; a partial read would
	// silently produce a wrong hash.
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

	// Compact proofs (proof_version 4): the challenge targets a single
	// 4096-byte BLOCK inside the challenged chunk. Everything above (object
	// lookup, chunk bounds, chunk read) is shared with V1 raw; only the proof
	// and the returned bytes differ. The provider holds no seal — it rebuilds
	// the sub-chunk tree from the chunk bytes here on every challenge.
	if ch.ProofVersion == proofVersionCompact {
		blockCount := subChunkBlockCount(len(chunkBuf))
		if ch.BlockIndex < 0 || ch.BlockIndex >= blockCount {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("block_index %d out of range [0, %d)", ch.BlockIndex, blockCount))
			return
		}
		block, siblings, err := generateSubChunkSiblings(chunkBuf, ch.BlockIndex)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "generate sub-chunk proof: "+err.Error())
			return
		}
		resp := auditResponse{
			Version:         ch.Version,
			ChallengeID:     ch.ChallengeID,
			ProviderID:      s.providerID,
			MerkleRoot:      ch.MerkleRoot,
			ChunkIndex:      ch.ChunkIndex,
			ChunkData:       base64.StdEncoding.EncodeToString(block),
			MerkleProof:     merkleProof{Siblings: siblings, Index: ch.BlockIndex},
			TotalChunkCount: idx.TotalChunks,
			Nonce:           ch.Nonce,
			Timestamp:       time.Now().Unix(),
			ProofVersion:    proofVersionCompact,
		}
		// Sign over the RAW returned block bytes and the compact block index.
		s.signAuditResponse(&resp, block, ch.BlockIndex)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Build merkle leaves from the precomputed chunk hashes.
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

	resp := auditResponse{
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
	}
	// V1 raw: signature is over the whole returned chunk; block index is 0.
	s.signAuditResponse(&resp, chunkBuf, 0)
	writeJSON(w, http.StatusOK, resp)
}

// signAuditResponse attaches the provider's signature + key id to a challenge
// response when a signer is configured. No-op when s.signer is nil, so
// unsigned (legacy/dev) providers emit the pre-signing wire format unchanged.
// The signature binds the response to this exact challenge and the returned
// bytes, so it cannot be replayed for a different challenge or tampered payload.
func (s *Server) signAuditResponse(resp *auditResponse, rawBytes []byte, blockIndex int) {
	if s.signer == nil {
		return
	}
	payload := identity.ProofSigPayload(
		resp.ProviderID,
		resp.ChallengeID,
		resp.Nonce,
		resp.MerkleRoot,
		resp.ChunkIndex,
		blockIndex,
		resp.ProofVersion,
		rawBytes,
	)
	resp.Signature = base64.StdEncoding.EncodeToString(s.signer.Sign(payload))
	resp.KeyID = s.signer.KeyID()
}
