package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/obsideo/obsideo-provider/store"
)

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	merkle := chi.URLParam(r, "merkle")

	// Verify token.
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

	chunkSize := store.DefaultChunkSize
	if cs := r.URL.Query().Get("chunk_size"); cs != "" {
		if n, err := strconv.Atoi(cs); err == nil && n > 0 {
			chunkSize = n
		}
	}

	// Read body.
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}

	if err := s.store.Put(merkle, data, chunkSize); err != nil {
		writeError(w, http.StatusInternalServerError, "store: "+err.Error())
		return
	}

	// Retention-authority Phase 1: if the upload token carries both
	// customer pubkeys, persist the ownership file at mode 0o444.
	// Legacy-account uploads (token missing OwnerSigPubkey) skip the
	// write entirely per docs/retention_authority_design.md §9.2 —
	// those objects are not subject to user-signed delete.
	//
	// The object bytes have already been written; an ownership write
	// failure here is an internal error but does not invalidate the
	// stored chunks. Respond 500 so the client knows something is
	// off; a retry will hit the ErrOwnershipExists branch and be
	// rejected (which is desired: if a malformed pass wrote a bad
	// ownership file, an operator should investigate rather than
	// silently overwriting).
	if claims.OwnerPubkey != "" && claims.OwnerSigPubkey != "" {
		own := store.Ownership{
			OwnerPubkey:    claims.OwnerPubkey,
			OwnerSigPubkey: claims.OwnerSigPubkey,
			ReceivedAt:     time.Now().UTC(),
		}
		if err := s.store.PutOwnership(merkle, own); err != nil {
			// Idempotency: if ownership already exists for this merkle,
			// the write-once invariant says we leave it alone and return
			// success — a replay of the same upload is expected to
			// converge on the same state, not overwrite.
			if !errors.Is(err, store.ErrOwnershipExists) {
				writeError(w, http.StatusInternalServerError, "store ownership: "+err.Error())
				return
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
