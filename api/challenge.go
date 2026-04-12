package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// ── Canonical Protocol Types ────────────────────────────────────────────────
// These types match coordinator/proof/types.go exactly.

const (
	proofVersionV1        = 2 // raw chunk audit
	proofVersionV1Replica = 3 // provider-bound replica audit
)

// auditChallenge matches the canonical protocol spec (00_canonical_protocol.md).
type auditChallenge struct {
	Version      int    `json:"version"`
	ChallengeID  string `json:"challenge_id"`
	MerkleRoot   string `json:"merkle_root"`              // hex, raw object root
	ProviderID   string `json:"provider_id,omitempty"`     // target provider
	ChunkIndex   int    `json:"chunk_index"`               // 0-based
	Nonce        string `json:"nonce"`                     // hex, 16 random bytes
	ExpiresAt    int64  `json:"expires_at"`                // unix timestamp
	ProofVersion int    `json:"proof_version,omitempty"`   // 2=raw, 3=replica
}

// auditResponse matches the canonical protocol spec.
type auditResponse struct {
	Version         int         `json:"version"`
	ChallengeID     string      `json:"challenge_id"`
	ProviderID      string      `json:"provider_id"`
	MerkleRoot      string      `json:"merkle_root"`
	ChunkIndex      int         `json:"chunk_index"`
	ChunkData       string      `json:"chunk_data"` // base64 encoded bytes
	MerkleProof     merkleProof `json:"merkle_proof"`
	TotalChunkCount int         `json:"total_chunk_count"`
	Nonce           string      `json:"nonce"`
	Timestamp       int64       `json:"timestamp"`
	ProofVersion    int         `json:"proof_version"` // echoed: confirms which mode was executed
}

// replicaCommitmentResponse is returned by POST /replica-commitment/{merkle}.
type replicaCommitmentResponse struct {
	ObjectMerkle       string   `json:"object_merkle"`
	ProviderID         string   `json:"provider_id"`
	ReplicaVersion     int      `json:"replica_version"`
	ReplicaRoot        string   `json:"replica_root"`
	ReplicaChunkHashes []string `json:"replica_chunk_hashes"`
	ChunkCount         int      `json:"chunk_count"`
}

type merkleProof struct {
	Siblings []string `json:"siblings"` // hex, bottom-up
	Index    int      `json:"index"`    // leaf position
}

// ── Challenge Handler ───────────────────────────────────────────────────────

// handleChallenge processes audit challenges from the coordinator.
// Supports both V1 raw-chunk mode (proof_version=2) and provider-bound
// replica mode (proof_version=3).
//
// POST /challenge
// Body: auditChallenge JSON
func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var ch auditChallenge
	if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	// Validate provider identity
	if ch.ProviderID != "" && ch.ProviderID != s.cfg.ProviderID {
		log.Warn().
			Str("expected", s.cfg.ProviderID).
			Str("got", ch.ProviderID).
			Msg("challenge provider_id mismatch")
		writeErr(w, http.StatusForbidden, "provider_id mismatch")
		return
	}

	// Check expiry
	if ch.ExpiresAt > 0 && time.Now().Unix() > ch.ExpiresAt {
		writeErr(w, http.StatusGone, "challenge expired")
		return
	}

	if ch.MerkleRoot == "" {
		writeErr(w, http.StatusBadRequest, "merkle_root required")
		return
	}

	merkleBytes, err := hex.DecodeString(ch.MerkleRoot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle_root hex")
		return
	}

	// Determine mode: replica (proof_version=3) or raw (proof_version=2 or 0)
	switch ch.ProofVersion {
	case proofVersionV1Replica:
		s.handleReplicaChallenge(w, ch, merkleBytes)
	case proofVersionV1, 0:
		s.handleRawChallenge(w, ch, merkleBytes)
	default:
		log.Warn().Int("proof_version", ch.ProofVersion).Msg("challenge: unknown proof_version")
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("unsupported proof_version %d", ch.ProofVersion))
	}
}

// handleRawChallenge handles V1 raw-chunk audit challenges.
func (s *Server) handleRawChallenge(w http.ResponseWriter, ch auditChallenge, merkleBytes []byte) {
	// Read the challenged chunk
	chunkData, totalChunks, err := s.fs.GetChunkByMerkle(merkleBytes, ch.ChunkIndex)
	if err != nil {
		log.Error().Err(err).Str("merkle", ch.MerkleRoot).Int("chunk", ch.ChunkIndex).Msg("challenge: chunk lookup failed")
		writeErr(w, http.StatusNotFound, "object or chunk not found")
		return
	}

	// Read all chunks to compute merkle proof
	allChunks, err := s.fs.GetAllChunks(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", ch.MerkleRoot).Msg("challenge: failed to read all chunks")
		writeErr(w, http.StatusInternalServerError, "failed to build merkle proof")
		return
	}

	// Build merkle tree leaves matching SDK formula:
	//   chunk_hash = SHA-256(fmt.Sprintf("%d%x", i, chunk))
	//   tree_leaf  = SHA3-512(chunk_hash)   (wealdtech pre-hash)
	leaves := make([][]byte, len(allChunks))
	for i, cd := range allChunks {
		chunkHash := chunkHashV1(i, cd)
		leaves[i] = sha3Sum512(chunkHash) // wealdtech pre-hash
	}

	siblings := computeMerkleProof(leaves, ch.ChunkIndex)

	resp := auditResponse{
		Version:         ch.Version,
		ChallengeID:     ch.ChallengeID,
		ProviderID:      s.cfg.ProviderID,
		MerkleRoot:      ch.MerkleRoot,
		ChunkIndex:      ch.ChunkIndex,
		ChunkData:       base64.StdEncoding.EncodeToString(chunkData),
		MerkleProof:     merkleProof{Siblings: siblings, Index: ch.ChunkIndex},
		TotalChunkCount: totalChunks,
		Nonce:           ch.Nonce,
		Timestamp:       time.Now().Unix(),
		ProofVersion:    proofVersionV1,
	}

	log.Info().Str("merkle", ch.MerkleRoot[:16]).Int("chunk", ch.ChunkIndex).Int("total", totalChunks).Msg("challenge passed (raw)")
	writeJSON(w, http.StatusOK, resp)
}

// handleReplicaChallenge handles provider-bound replica audit challenges.
// The provider reads raw bytes from storage, applies the deterministic
// provider-bound transform, and returns the replica bytes with a merkle
// proof computed over the replica leaves.
func (s *Server) handleReplicaChallenge(w http.ResponseWriter, ch auditChallenge, merkleBytes []byte) {
	// Read all raw chunks from storage
	allRawChunks, err := s.fs.GetAllChunks(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", ch.MerkleRoot).Msg("replica challenge: failed to read chunks")
		writeErr(w, http.StatusNotFound, "object or chunk not found")
		return
	}

	if ch.ChunkIndex < 0 || ch.ChunkIndex >= len(allRawChunks) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("chunk_index %d out of range", ch.ChunkIndex))
		return
	}

	// Derive replica key using canonical derivation
	// Must match coordinator/proof/replica.go exactly.
	replicaVersion := 1 // v1.5 canonical version
	key, err := deriveReplicaKey(s.cfg.ProviderID, ch.MerkleRoot, replicaVersion)
	if err != nil {
		log.Error().Err(err).Msg("replica challenge: key derivation failed")
		writeErr(w, http.StatusInternalServerError, "replica key derivation failed")
		return
	}

	// Transform all chunks and build replica merkle tree
	replicaLeaves := make([][]byte, len(allRawChunks))
	var challengedReplicaChunk []byte

	for i, rawChunk := range allRawChunks {
		replicaChunk, err := encodeReplicaChunk(key, i, rawChunk)
		if err != nil {
			log.Error().Err(err).Int("chunk", i).Msg("replica challenge: encode failed")
			writeErr(w, http.StatusInternalServerError, "replica encoding failed")
			return
		}

		if i == ch.ChunkIndex {
			challengedReplicaChunk = replicaChunk
		}

		chunkHash := sha3Sum512(replicaChunk)
		replicaLeaves[i] = sha3Sum512(chunkHash) // wealdtech pre-hash
	}

	siblings := computeMerkleProof(replicaLeaves, ch.ChunkIndex)

	resp := auditResponse{
		Version:         ch.Version,
		ChallengeID:     ch.ChallengeID,
		ProviderID:      s.cfg.ProviderID,
		MerkleRoot:      ch.MerkleRoot,
		ChunkIndex:      ch.ChunkIndex,
		ChunkData:       base64.StdEncoding.EncodeToString(challengedReplicaChunk),
		MerkleProof:     merkleProof{Siblings: siblings, Index: ch.ChunkIndex},
		TotalChunkCount: len(allRawChunks),
		Nonce:           ch.Nonce,
		Timestamp:       time.Now().Unix(),
		ProofVersion:    proofVersionV1Replica,
	}

	log.Info().Str("merkle", ch.MerkleRoot[:16]).Int("chunk", ch.ChunkIndex).Int("total", len(allRawChunks)).Msg("challenge passed (replica)")
	writeJSON(w, http.StatusOK, resp)
}

// handleReplicaCommitment computes the provider-bound replica commitment
// for a stored object. Called by the coordinator during upload confirmation
// to ensure commitments exist before any audit fires.
//
// POST /replica-commitment/{merkle}
func (s *Server) handleReplicaCommitment(w http.ResponseWriter, r *http.Request) {
	merkleHex := mux.Vars(r)["merkle"]
	merkleBytes, err := hex.DecodeString(merkleHex)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle hex")
		return
	}

	allRawChunks, err := s.fs.GetAllChunks(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", merkleHex).Msg("replica-commitment: failed to read chunks")
		writeErr(w, http.StatusNotFound, "object not found")
		return
	}

	replicaVersion := 1
	key, err := deriveReplicaKey(s.cfg.ProviderID, merkleHex, replicaVersion)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key derivation failed")
		return
	}

	replicaHashes := make([]string, len(allRawChunks))
	replicaLeaves := make([][]byte, len(allRawChunks))

	for i, rawChunk := range allRawChunks {
		replicaChunk, err := encodeReplicaChunk(key, i, rawChunk)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encode failed")
			return
		}
		chunkHash := sha3Sum512(replicaChunk)
		replicaHashes[i] = hex.EncodeToString(chunkHash)
		replicaLeaves[i] = sha3Sum512(chunkHash)
	}

	root := buildMerkleRoot(replicaLeaves)

	writeJSON(w, http.StatusOK, replicaCommitmentResponse{
		ObjectMerkle:       merkleHex,
		ProviderID:         s.cfg.ProviderID,
		ReplicaVersion:     replicaVersion,
		ReplicaRoot:        hex.EncodeToString(root),
		ReplicaChunkHashes: replicaHashes,
		ChunkCount:         len(allRawChunks),
	})
}

// ── Canonical Replica Derivation ────────────────────────────────────────────
// These functions MUST exactly match coordinator/proof/replica.go.
// They exist here because the provider is a separate Go module.
//
// Canonical formula:
//   canonical_salt = SHA256("obsideo-replica-salt-v1:" || object_id)
//   hkdf_salt = SHA256(provider_id || object_id || le32(version))
//   key = HKDF-SHA256(IKM: canonical_salt, salt: hkdf_salt, info: "obsideo-replica-v1") -> 32 bytes
//   replica_chunk[i] = AES-256-CTR(key, iv: le64(i)||zeros, plaintext: raw_chunk[i])

func deriveReplicaKey(providerID, objectID string, version int) ([]byte, error) {
	// IKM = SHA256("obsideo-replica-salt-v1:" + objectID)
	ikmHash := sha256.Sum256([]byte("obsideo-replica-salt-v1:" + objectID))

	// salt = SHA256(providerID || objectID || le32(version))
	sh := sha256.New()
	sh.Write([]byte(providerID))
	sh.Write([]byte(objectID))
	var vBuf [4]byte
	binary.LittleEndian.PutUint32(vBuf[:], uint32(version))
	sh.Write(vBuf[:])
	salt := sh.Sum(nil)

	hk := hkdf.New(sha256.New, ikmHash[:], salt, []byte("obsideo-replica-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}

func encodeReplicaChunk(key []byte, chunkIndex int, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	var iv [aes.BlockSize]byte
	binary.LittleEndian.PutUint64(iv[:8], uint64(chunkIndex))
	stream := cipher.NewCTR(block, iv[:])
	output := make([]byte, len(plaintext))
	stream.XORKeyStream(output, plaintext)
	return output, nil
}

// buildMerkleRoot constructs a merkle root from leaves using canonical SHA3-512.
// Must match coordinator/proof/replica.go buildMerkleRoot exactly.
// buildMerkleRoot constructs a wealdtech-compatible merkle root from pre-hashed
// leaves. Zero-pads to next power of 2 to match the SDK's tree construction.
func buildMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	target := nextPow2(len(leaves))
	level := make([][]byte, target)
	copy(level, leaves)
	for i := len(leaves); i < target; i++ {
		level[i] = make([]byte, hashLen) // zero-hash padding
	}

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			h := sha3.New512()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}

// ── Shared Crypto Utilities ─────────────────────────────────────────────────

// chunkHashV1 computes the V1 chunk hash: SHA-256(fmt.Sprintf("%d%x", index, rawBytes)).
// Matches the SDK (merkle.ts buildTree) and provider (file_system.go BuildTree).
func chunkHashV1(index int, rawBytes []byte) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d%x", index, rawBytes)
	return h.Sum(nil)
}

// sha3Sum512 computes SHA3-512 of data.
func sha3Sum512(data []byte) []byte {
	h := sha3.New512()
	h.Write(data)
	return h.Sum(nil)
}

// hashLen is the SHA3-512 output length in bytes.
const hashLen = 64

// nextPow2 returns the smallest power of 2 >= n.
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	v := 1
	for v < n {
		v <<= 1
	}
	return v
}

// computeMerkleProof builds the sibling list from leaf to root for the given
// leaf index. Uses zero-padding to next power of 2 to match the SDK's
// wealdtech-compatible tree construction.
func computeMerkleProof(leaves [][]byte, leafIndex int) []string {
	if len(leaves) <= 1 {
		return []string{}
	}

	target := nextPow2(len(leaves))
	level := make([][]byte, target)
	copy(level, leaves)
	for i := len(leaves); i < target; i++ {
		level[i] = make([]byte, hashLen) // zero-hash padding
	}

	var siblings []string
	idx := leafIndex

	for len(level) > 1 {
		if idx%2 == 0 {
			siblings = append(siblings, hex.EncodeToString(level[idx+1]))
		} else {
			siblings = append(siblings, hex.EncodeToString(level[idx-1]))
		}

		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			h := sha3.New512()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
		idx /= 2
	}

	return siblings
}
