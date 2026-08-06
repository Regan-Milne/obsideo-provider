package api

import (
	"errors"
	"net/http"
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

	// accept_uncontracted_data gate. Same Contracted predicate the GC
	// sweeper consumes; enforced at ingress instead of at retention-window
	// expiry. Default-true at the config layer (pass-through behavior);
	// operators set false to refuse testdrive / expired-paid / unregistered
	// uploads. Bytes never touch disk when the gate fires.
	if !claims.Contracted && !s.acceptUncontractedData {
		writeError(w, http.StatusForbidden,
			"this provider's accept_uncontracted_data policy is false; non-contracted uploads are refused at the boundary")
		return
	}

	// Stream the body to disk while hashing the merkle frontier
	// incrementally, then verify the computed root against the URL/token
	// merkle at close. Bounded memory regardless of object size (replaces
	// the io.ReadAll + full-buffer Put that capped large objects at
	// RAM ÷ concurrency). The chunk size is frozen at 1 MiB network-wide —
	// the merkle root is only defined at 1 MiB — so no chunk_size param is
	// honored here; the index PutStream writes is always 1 MiB.
	if _, err := s.store.PutStream(merkle, r.Body); err != nil {
		if errors.Is(err, store.ErrMerkleMismatch) {
			// Bytes do not hash to the claimed root: a content-addressing
			// violation, not a server fault. Nothing was stored.
			writeError(w, http.StatusUnprocessableEntity,
				"uploaded bytes do not hash to merkle root "+merkle)
			return
		}
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
