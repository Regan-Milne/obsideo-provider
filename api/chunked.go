package api

// Chunked upload handlers — ported from provider/api/chunked.go (legacy
// tree, commit dd22176 from 2026-04-06). Same wire protocol that the
// SDK has been using in production since then. Adaptations from legacy:
//
//   - chi.URLParam instead of mux.Vars (provider-clean uses chi)
//   - bearerToken returns (string, error) here, not (string, bool)
//   - Token claims accessed as *tokens.Claims (legacy used a different
//     local Claims type)
//   - Finalize calls s.store.Put for assembly + index write (legacy
//     called s.fs.WriteFile against IPFS)
//   - Staging paths come from Store.StagingDirPath / StagingChunkPath /
//     StagingMetaPath / RemoveStaging
//   - Finalize honors the accept_uncontracted_data policy gate the same
//     way the single-shot upload handler does — bytes that the gate
//     rejects must not graduate from staging into objects/. Per-chunk
//     handlers do NOT gate on Contracted because the token signature is
//     the same on every chunk; checking once at /chunk index 0 would
//     just duplicate the finalize check, and gating on every chunk would
//     not save the bytes already in staging from the chunk that opened
//     the staging dir. The gate's load-bearing assertion is "uncontracted
//     bytes never land in objects/" — staging/ is ephemeral and gets
//     RemoveStaging'd on finalize regardless of outcome.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/obsideo/obsideo-provider/store"
)

// handleUploadChunk stores a single transport chunk for a large file
// upload.
//
// POST /upload/{merkle}/chunk?index=N&total=M
//
//	Authorization: Bearer <upload_token>
//	Body: raw chunk bytes
//
// Idempotent: re-uploading the same index overwrites the previous
// chunk file.
func (s *Server) handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	merkle := chi.URLParam(r, "merkle")

	tok, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	claims, err := s.verifier.Verify(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if claims.Type != "upload" {
		writeError(w, http.StatusForbidden, "expected upload token")
		return
	}
	if claims.MerkleRoot != merkle {
		writeError(w, http.StatusForbidden, "token merkle_root does not match URL")
		return
	}

	indexStr := r.URL.Query().Get("index")
	totalStr := r.URL.Query().Get("total")
	if indexStr == "" || totalStr == "" {
		writeError(w, http.StatusBadRequest, "index and total query params required")
		return
	}
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}
	total, err := strconv.Atoi(totalStr)
	if err != nil || total <= 0 {
		writeError(w, http.StatusBadRequest, "invalid total")
		return
	}
	if index >= total {
		writeError(w, http.StatusBadRequest, "index must be < total")
		return
	}

	dir := s.store.StagingDirPath(merkle)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "staging mkdir: "+err.Error())
		return
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read chunk body")
		return
	}
	if len(data) == 0 {
		writeError(w, http.StatusBadRequest, "empty chunk")
		return
	}

	if err := os.WriteFile(s.store.StagingChunkPath(merkle, index), data, 0o644); err != nil {
		writeError(w, http.StatusInternalServerError, "write chunk: "+err.Error())
		return
	}
	// Record total so finalize knows how many chunks to expect.
	_ = os.WriteFile(s.store.StagingMetaPath(merkle), []byte(totalStr), 0o644)

	writeJSON(w, http.StatusOK, map[string]any{
		"index":    index,
		"received": len(data),
	})
}

// handleUploadFinalize assembles staged chunks, persists via store.Put
// (which atomically writes objects/{merkle} + index/{merkle}.json),
// writes the ownership file when the token carries both customer pubkeys,
// and removes staging.
//
// POST /upload/{merkle}/finalize
//
//	Authorization: Bearer <upload_token>
//	Query params: chunk_size (optional, defaults to store.DefaultChunkSize)
//
// The accept_uncontracted_data gate fires here, mirroring single-shot
// upload behavior — bytes never graduate from staging to objects/ when
// the operator has opted out of non-contracted uploads.
func (s *Server) handleUploadFinalize(w http.ResponseWriter, r *http.Request) {
	merkle := chi.URLParam(r, "merkle")

	tok, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	claims, err := s.verifier.Verify(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if claims.Type != "upload" {
		writeError(w, http.StatusForbidden, "expected upload token")
		return
	}
	if claims.MerkleRoot != merkle {
		writeError(w, http.StatusForbidden, "token merkle_root does not match URL")
		return
	}

	// accept_uncontracted_data gate. Same check as the single-shot
	// upload handler. Reject before assembling so the staged chunks get
	// cleaned up without ever passing through Put.
	if !claims.Contracted && !s.acceptUncontractedData {
		_ = s.store.RemoveStaging(merkle)
		writeError(w, http.StatusForbidden,
			"this provider's accept_uncontracted_data policy is false; non-contracted uploads are refused at the boundary")
		return
	}

	metaBytes, err := os.ReadFile(s.store.StagingMetaPath(merkle))
	if err != nil {
		writeError(w, http.StatusBadRequest, "no staged chunks found for this merkle")
		return
	}
	total, _ := strconv.Atoi(strings.TrimSpace(string(metaBytes)))
	if total <= 0 {
		writeError(w, http.StatusBadRequest, "invalid chunk total")
		return
	}

	// Verify all chunks are present before assembling.
	for i := 0; i < total; i++ {
		if _, err := os.Stat(s.store.StagingChunkPath(merkle, i)); os.IsNotExist(err) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("missing chunk %d of %d", i, total))
			return
		}
	}

	// Assemble. Same memory profile as the legacy implementation —
	// the assembled buffer is sized to the full ciphertext. For very
	// large uploads this is bounded by available RAM; the SDK's 5 MB
	// transport-chunk size keeps individual reads small but the
	// merkle-verifying Put still needs the full buffer in one call.
	var assembled []byte
	for i := 0; i < total; i++ {
		chunk, err := os.ReadFile(s.store.StagingChunkPath(merkle, i))
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("read chunk %d: %v", i, err))
			return
		}
		assembled = append(assembled, chunk...)
	}

	chunkSize := store.DefaultChunkSize
	if v := r.URL.Query().Get("chunk_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			chunkSize = n
		}
	}

	if err := s.store.Put(merkle, assembled, chunkSize); err != nil {
		writeError(w, http.StatusInternalServerError, "store: "+err.Error())
		return
	}

	// Mirror upload.go's ownership-file behavior. The same comment
	// applies: if the token carries both pubkeys, persist a write-once
	// ownership record; ErrOwnershipExists on retry is treated as
	// success (idempotent).
	if claims.OwnerPubkey != "" && claims.OwnerSigPubkey != "" {
		own := store.Ownership{
			OwnerPubkey:    claims.OwnerPubkey,
			OwnerSigPubkey: claims.OwnerSigPubkey,
			ReceivedAt:     time.Now().UTC(),
		}
		if err := s.store.PutOwnership(merkle, own); err != nil {
			if !errors.Is(err, store.ErrOwnershipExists) {
				writeError(w, http.StatusInternalServerError, "store ownership: "+err.Error())
				return
			}
		}
	}

	_ = s.store.RemoveStaging(merkle)

	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_root": merkle,
		"size_bytes":  len(assembled),
	})
}

// handleUploadStatus returns the indices of staged chunks for an
// in-progress upload. Used by the SDK to resume after a network drop.
//
// GET /upload/{merkle}/status
//
//	Authorization: Bearer <upload_token>
func (s *Server) handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	merkle := chi.URLParam(r, "merkle")

	tok, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	claims, err := s.verifier.Verify(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if claims.Type != "upload" {
		writeError(w, http.StatusForbidden, "expected upload token")
		return
	}
	if claims.MerkleRoot != merkle {
		writeError(w, http.StatusForbidden, "token merkle_root does not match URL")
		return
	}

	dir := s.store.StagingDirPath(merkle)
	entries, err := os.ReadDir(dir)
	if err != nil {
		// No staging dir means no chunks have been received yet.
		writeJSON(w, http.StatusOK, map[string]any{
			"merkle":   merkle,
			"chunks":   []int{},
			"total":    0,
			"complete": false,
		})
		return
	}

	var total int
	if metaBytes, err := os.ReadFile(s.store.StagingMetaPath(merkle)); err == nil {
		total, _ = strconv.Atoi(strings.TrimSpace(string(metaBytes)))
	}

	var indices []int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "chunk_") {
			if idx, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "chunk_")); err == nil {
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
