package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	providerTypes "github.com/Regan-Milne/obsideo-provider/types"
	"github.com/rs/zerolog/log"
)

const stagingDir = "staging"

func (s *Server) stagingPath(merkle string) string {
	return filepath.Join(s.cfg.DB.Path, stagingDir, merkle)
}

func (s *Server) chunkPath(merkle string, index int) string {
	return filepath.Join(s.stagingPath(merkle), fmt.Sprintf("chunk_%05d", index))
}

// handleUploadChunk stores a single transport chunk for a large file upload.
//
// POST /upload/{merkle}/chunk?index=N&total=M
//
//	Authorization: Bearer <upload_token>
//	Body: raw chunk bytes
//
// Idempotent: re-uploading the same index overwrites the previous chunk.
func (s *Server) handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	merkle := mux.Vars(r)["merkle"]

	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing Authorization header")
		return
	}
	claims, err := s.ver.Verify(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}
	if claims.Type != "upload" || claims.MerkleRoot != merkle {
		writeErr(w, http.StatusForbidden, "token mismatch")
		return
	}

	indexStr := r.URL.Query().Get("index")
	totalStr := r.URL.Query().Get("total")
	if indexStr == "" || totalStr == "" {
		writeErr(w, http.StatusBadRequest, "index and total query params required")
		return
	}
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 {
		writeErr(w, http.StatusBadRequest, "invalid index")
		return
	}
	total, err := strconv.Atoi(totalStr)
	if err != nil || total <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid total")
		return
	}
	if index >= total {
		writeErr(w, http.StatusBadRequest, "index must be < total")
		return
	}

	dir := s.stagingPath(merkle)
	if err := os.MkdirAll(dir, 0755); err != nil {
		writeErr(w, http.StatusInternalServerError, "staging mkdir: "+err.Error())
		return
	}

	// Write chunk to staging file
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "failed to read chunk body")
		return
	}
	if len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "empty chunk")
		return
	}

	path := s.chunkPath(merkle, index)
	if err := os.WriteFile(path, data, 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, "write chunk: "+err.Error())
		return
	}

	// Also store total count for finalize
	metaPath := filepath.Join(dir, "meta")
	os.WriteFile(metaPath, []byte(totalStr), 0644)

	log.Info().
		Str("merkle", merkle[:16]).
		Int("index", index).
		Int("total", total).
		Int("bytes", len(data)).
		Msg("chunk received")

	writeJSON(w, http.StatusOK, map[string]any{
		"index":    index,
		"received": len(data),
	})
}

// handleUploadFinalize assembles all staged chunks, runs merkle verification
// via the existing WriteFile path, and stores to IPFS.
//
// POST /upload/{merkle}/finalize
//
//	Authorization: Bearer <upload_token>
//	Query params: same as regular upload (owner, chunk_size, proof_type)
func (s *Server) handleUploadFinalize(w http.ResponseWriter, r *http.Request) {
	merkle := mux.Vars(r)["merkle"]

	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing Authorization header")
		return
	}
	claims, err := s.ver.Verify(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}
	if claims.Type != "upload" || claims.MerkleRoot != merkle {
		writeErr(w, http.StatusForbidden, "token mismatch")
		return
	}

	dir := s.stagingPath(merkle)

	// Read total from meta
	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "no staged chunks found for this merkle")
		return
	}
	total, _ := strconv.Atoi(strings.TrimSpace(string(metaBytes)))
	if total <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid chunk total")
		return
	}

	// Verify all chunks exist
	for i := 0; i < total; i++ {
		if _, err := os.Stat(s.chunkPath(merkle, i)); os.IsNotExist(err) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("missing chunk %d of %d", i, total))
			return
		}
	}

	// Assemble chunks into full file
	log.Info().Str("merkle", merkle[:16]).Int("chunks", total).Msg("finalize: assembling")
	tAssemble := time.Now()

	var assembled []byte
	for i := 0; i < total; i++ {
		chunk, err := os.ReadFile(s.chunkPath(merkle, i))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, fmt.Sprintf("read chunk %d: %s", i, err))
			return
		}
		assembled = append(assembled, chunk...)
	}

	log.Info().
		Str("merkle", merkle[:16]).
		Int("total_bytes", len(assembled)).
		Dur("assemble_dur", time.Since(tAssemble)).
		Msg("finalize: assembled")

	// Parse query params (same as regular upload)
	owner := r.URL.Query().Get("owner")
	if owner == "" {
		owner = claims.AccountID
	}
	chunkSize := int64(1048576) // 1 MiB default
	if v := r.URL.Query().Get("chunk_size"); v != "" {
		chunkSize, _ = strconv.ParseInt(v, 10, 64)
	}
	proofType := int64(0)
	if v := r.URL.Query().Get("proof_type"); v != "" {
		proofType, _ = strconv.ParseInt(v, 10, 64)
	}

	// Use existing WriteFile path for merkle verification + storage
	merkleBytes, err := hexDecode(merkle)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle hex")
		return
	}

	tWrite := time.Now()
	reader := providerTypes.NewBytesSeeker(assembled)
	size, err := s.fs.WriteFile(reader, merkleBytes, owner, 0, chunkSize, proofType)
	if err != nil {
		log.Error().Err(err).Str("merkle", merkle[:16]).Msg("finalize: write failed")
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("write failed: %s", err))
		return
	}

	// Clean up staging
	os.RemoveAll(dir)

	log.Info().
		Str("merkle", merkle[:16]).
		Int("size", size).
		Dur("write_dur", time.Since(tWrite)).
		Msg("finalize: stored")

	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_root": merkle,
		"size_bytes":  size,
	})
}

// handleUploadStatus returns which chunks have been staged for a merkle root.
// Used by the SDK to resume interrupted uploads.
//
// GET /upload/{merkle}/status
func (s *Server) handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	merkle := mux.Vars(r)["merkle"]

	// Require a valid upload token to check status.
	tok, ok := bearerToken(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing Authorization header")
		return
	}
	claims, err := s.ver.Verify(tok)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}
	if claims.Type != "upload" || claims.MerkleRoot != merkle {
		writeErr(w, http.StatusForbidden, "token mismatch")
		return
	}

	dir := s.stagingPath(merkle)

	entries, err := os.ReadDir(dir)
	if err != nil {
		// No staging dir = no chunks
		writeJSON(w, http.StatusOK, map[string]any{
			"merkle":   merkle,
			"chunks":   []int{},
			"total":    0,
			"complete": false,
		})
		return
	}

	var total int
	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta"))
	if err == nil {
		total, _ = strconv.Atoi(strings.TrimSpace(string(metaBytes)))
	}

	var indices []int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "chunk_") {
			idx, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "chunk_"))
			if err == nil {
				indices = append(indices, idx)
			}
		}
	}
	sort.Ints(indices)

	writeJSON(w, http.StatusOK, map[string]any{
		"merkle":   merkle,
		"chunks":   indices,
		"total":    total,
		"complete": total > 0 && len(indices) == total,
	})
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi := unhex(s[2*i])
		lo := unhex(s[2*i+1])
		if hi == 0xff || lo == 0xff {
			return nil, fmt.Errorf("invalid hex at position %d", 2*i)
		}
		b[i] = hi<<4 | lo
	}
	return b, nil
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xff
	}
}
