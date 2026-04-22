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
	"github.com/Regan-Milne/obsideo-provider/file_system"
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

// handleRawChallenge handles V1 raw-chunk audit challenges. Streaming
// implementation: reads chunks sequentially from disk, hashes each leaf into
// a small accumulator, keeps only the challenged chunk's bytes for the
// response. Peak memory is O(chunk_size + N*64 bytes), not O(file_size).
func (s *Server) handleRawChallenge(w http.ResponseWriter, ch auditChallenge, merkleBytes []byte) {
	rsc, err := s.fs.GetFileData(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", ch.MerkleRoot).Msg("challenge: failed to open object")
		writeErr(w, http.StatusNotFound, "object or chunk not found")
		return
	}
	defer rsc.Close()

	fileSize, err := rsc.Seek(0, io.SeekEnd)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "file seek failed")
		return
	}
	if _, err := rsc.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, "file seek failed")
		return
	}

	chunkSize := int64(file_system.DefaultChunkSize)
	totalChunks := int((fileSize + chunkSize - 1) / chunkSize)
	if totalChunks == 0 {
		writeErr(w, http.StatusBadRequest, "object is empty")
		return
	}
	if ch.ChunkIndex < 0 || ch.ChunkIndex >= totalChunks {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("chunk_index %d out of range [0, %d)", ch.ChunkIndex, totalChunks))
		return
	}

	leaves := make([][]byte, totalChunks)
	var challengedChunkData []byte
	readBuf := make([]byte, chunkSize)

	for i := 0; i < totalChunks; i++ {
		n, rerr := io.ReadFull(rsc, readBuf)
		if rerr == io.EOF && n == 0 {
			writeErr(w, http.StatusInternalServerError, "file read truncated")
			return
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			writeErr(w, http.StatusInternalServerError, "file read failed")
			return
		}
		chunk := readBuf[:n]

		if i == ch.ChunkIndex {
			// Keep a copy; readBuf is reused on the next iteration.
			challengedChunkData = make([]byte, n)
			copy(challengedChunkData, chunk)
		}

		// SDK leaf formula: chunk_hash = SHA-256(fmt.Sprintf("%d%x", i, chunk))
		// then SHA3-512 pre-hash to produce the wealdtech-compatible tree leaf.
		chunkHash := chunkHashV1(i, chunk)
		leaves[i] = sha3Sum512(chunkHash)
	}

	siblings := computeMerkleProof(leaves, ch.ChunkIndex)

	resp := auditResponse{
		Version:         ch.Version,
		ChallengeID:     ch.ChallengeID,
		ProviderID:      s.cfg.ProviderID,
		MerkleRoot:      ch.MerkleRoot,
		ChunkIndex:      ch.ChunkIndex,
		ChunkData:       base64.StdEncoding.EncodeToString(challengedChunkData),
		MerkleProof:     merkleProof{Siblings: siblings, Index: ch.ChunkIndex},
		TotalChunkCount: totalChunks,
		Nonce:           ch.Nonce,
		Timestamp:       time.Now().Unix(),
		ProofVersion:    proofVersionV1,
	}

	log.Info().Str("merkle", ch.MerkleRoot[:16]).Int("chunk", ch.ChunkIndex).Int("total", totalChunks).Msg("challenge passed (raw, streaming)")
	writeJSON(w, http.StatusOK, resp)
}

// handleReplicaChallenge handles provider-bound replica audit challenges.
// The provider reads raw bytes from storage one chunk at a time, applies the
// deterministic provider-bound transform chunk-by-chunk, and returns the
// challenged replica chunk plus a merkle proof computed over the replica
// leaves. Peak memory during a challenge is O(chunk_size + N*64 bytes), not
// O(file_size), so resource-constrained providers can audit large objects
// without OOMing or exceeding the coordinator's HTTP timeout.
//
// Crypto properties are unchanged from the prior all-chunks-in-memory
// implementation: same replica key derivation, same AES-256-CTR transform
// with IV=le64(i), same SHA3-512 leaf hashing (pre-hashed once,
// wealdtech-compatible), same merkle proof construction, same wire format
// and proof version. A coordinator verifier cannot tell this response from
// one produced by the prior handler given the same inputs.
func (s *Server) handleReplicaChallenge(w http.ResponseWriter, ch auditChallenge, merkleBytes []byte) {
	// Open the object as a seekable file; we read chunks sequentially and
	// never hold more than one chunk's raw bytes in memory at once.
	rsc, err := s.fs.GetFileData(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", ch.MerkleRoot).Msg("replica challenge: failed to open object")
		writeErr(w, http.StatusNotFound, "object or chunk not found")
		return
	}
	defer rsc.Close()

	fileSize, err := rsc.Seek(0, io.SeekEnd)
	if err != nil {
		log.Error().Err(err).Msg("replica challenge: seek-end failed")
		writeErr(w, http.StatusInternalServerError, "file seek failed")
		return
	}
	if _, err := rsc.Seek(0, io.SeekStart); err != nil {
		log.Error().Err(err).Msg("replica challenge: seek-start failed")
		writeErr(w, http.StatusInternalServerError, "file seek failed")
		return
	}

	chunkSize := int64(file_system.DefaultChunkSize)
	totalChunks := int((fileSize + chunkSize - 1) / chunkSize)
	if totalChunks == 0 {
		writeErr(w, http.StatusBadRequest, "object is empty")
		return
	}
	if ch.ChunkIndex < 0 || ch.ChunkIndex >= totalChunks {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("chunk_index %d out of range [0, %d)", ch.ChunkIndex, totalChunks))
		return
	}

	// Derive replica key. Must match coordinator/proof/replica.go exactly.
	replicaVersion := 1
	key, err := deriveReplicaKey(s.cfg.ProviderID, ch.MerkleRoot, replicaVersion)
	if err != nil {
		log.Error().Err(err).Msg("replica challenge: key derivation failed")
		writeErr(w, http.StatusInternalServerError, "replica key derivation failed")
		return
	}

	replicaLeaves := make([][]byte, totalChunks)
	var challengedReplicaChunk []byte
	readBuf := make([]byte, chunkSize) // reusable input buffer

	for i := 0; i < totalChunks; i++ {
		// io.ReadFull handles short reads. The last chunk is expected to be
		// smaller than chunkSize in general; io.ErrUnexpectedEOF at that point
		// is not a real error — the partial-buffer slice captures the tail.
		n, rerr := io.ReadFull(rsc, readBuf)
		if rerr == io.EOF && n == 0 {
			log.Error().Int("chunk", i).Int("total", totalChunks).Msg("replica challenge: unexpected EOF before last chunk")
			writeErr(w, http.StatusInternalServerError, "file read truncated")
			return
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			log.Error().Err(rerr).Int("chunk", i).Msg("replica challenge: read failed")
			writeErr(w, http.StatusInternalServerError, "file read failed")
			return
		}
		rawChunk := readBuf[:n]

		// encodeReplicaChunk allocates a fresh output slice (AES-CTR over the
		// input), so the chunk's bytes are independent of readBuf and safe to
		// reference past the next iteration's overwrite of readBuf.
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
		// Non-challenged replicaChunk goes out of scope here; Go GC can reclaim
		// it on the next allocation. Peak resident chunk bytes during the loop
		// is at most two: the one being processed, and the challenged one we
		// need to keep for the response.
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
		TotalChunkCount: totalChunks,
		Nonce:           ch.Nonce,
		Timestamp:       time.Now().Unix(),
		ProofVersion:    proofVersionV1Replica,
	}

	log.Info().Str("merkle", ch.MerkleRoot[:16]).Int("chunk", ch.ChunkIndex).Int("total", totalChunks).Msg("challenge passed (replica, streaming)")
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

	// Streaming implementation: read chunks sequentially and only keep the
	// O(N*64) replica leaf + chunk-hash hex strings, never the raw or
	// transformed chunk bytes of more than one chunk at a time. This is the
	// upload-time path — if it OOMs (as it did on resource-constrained
	// providers for large objects), the coordinator never stores a
	// ReplicaCommitment for that (object, provider) pair, and future
	// challenges silently fall back to V1 raw mode (which had the same
	// all-chunks-in-memory bug until this same commit). So this handler was
	// the root cause of the large-file failure cascade on small-RAM nodes.
	rsc, err := s.fs.GetFileData(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", merkleHex).Msg("replica-commitment: failed to open object")
		writeErr(w, http.StatusNotFound, "object not found")
		return
	}
	defer rsc.Close()

	fileSize, err := rsc.Seek(0, io.SeekEnd)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "file seek failed")
		return
	}
	if _, err := rsc.Seek(0, io.SeekStart); err != nil {
		writeErr(w, http.StatusInternalServerError, "file seek failed")
		return
	}

	chunkSize := int64(file_system.DefaultChunkSize)
	totalChunks := int((fileSize + chunkSize - 1) / chunkSize)
	if totalChunks == 0 {
		writeErr(w, http.StatusBadRequest, "object is empty")
		return
	}

	replicaVersion := 1
	key, err := deriveReplicaKey(s.cfg.ProviderID, merkleHex, replicaVersion)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key derivation failed")
		return
	}

	replicaHashes := make([]string, totalChunks)
	replicaLeaves := make([][]byte, totalChunks)
	readBuf := make([]byte, chunkSize)

	for i := 0; i < totalChunks; i++ {
		n, rerr := io.ReadFull(rsc, readBuf)
		if rerr == io.EOF && n == 0 {
			writeErr(w, http.StatusInternalServerError, "file read truncated")
			return
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			writeErr(w, http.StatusInternalServerError, "file read failed")
			return
		}
		rawChunk := readBuf[:n]

		replicaChunk, err := encodeReplicaChunk(key, i, rawChunk)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "encode failed")
			return
		}
		chunkHash := sha3Sum512(replicaChunk)
		replicaHashes[i] = hex.EncodeToString(chunkHash)
		replicaLeaves[i] = sha3Sum512(chunkHash)
		// replicaChunk goes out of scope here; Go GC reclaims it on the next
		// allocation. Only the 64-byte hash and its hex string persist.
	}

	root := buildMerkleRoot(replicaLeaves)

	writeJSON(w, http.StatusOK, replicaCommitmentResponse{
		ObjectMerkle:       merkleHex,
		ProviderID:         s.cfg.ProviderID,
		ReplicaVersion:     replicaVersion,
		ReplicaRoot:        hex.EncodeToString(root),
		ReplicaChunkHashes: replicaHashes,
		ChunkCount:         totalChunks,
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
