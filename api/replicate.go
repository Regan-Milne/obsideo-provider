package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// replicateRequest matches the body the coordinator's Replicator.ReplicateTo
// sends. Field names must stay aligned with coordinator/replicator/replicator.go
// and with provider/api/replicate.go (the legacy provider); all three speak
// the same wire format so coord-triggered replication works against any
// provider implementation.
type replicateRequest struct {
	SourceURL     string `json:"source_url"`
	MerkleRoot    string `json:"merkle_root"`
	Owner         string `json:"owner"`
	Start         int64  `json:"start"`
	ChunkSize     int64  `json:"chunk_size"`
	ProofType     int64  `json:"proof_type"`
	UploadToken   string `json:"upload_token"`   // for storing on this provider
	DownloadToken string `json:"download_token"` // for fetching from source provider
}

// handleReplicate pulls bytes from a source provider (via its /download
// endpoint using download_token) and stores them locally after verifying
// the coordinator's upload_token for this merkle. Idempotent via the
// store's atomic write — re-replicating the same merkle overwrites
// cleanly.
func (s *Server) handleReplicate(w http.ResponseWriter, r *http.Request) {
	var req replicateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if req.SourceURL == "" || req.MerkleRoot == "" || req.UploadToken == "" {
		writeError(w, http.StatusBadRequest, "source_url, merkle_root, and upload_token required")
		return
	}
	// ChunkSize is accepted for wire compatibility with the coordinator's
	// replicator but no longer consumed: the merkle index is always written
	// at the frozen 1 MiB chunk size by PutStream.

	// Verify the coordinator's upload token. This is what authorizes the
	// replication — the coord issued it for this merkle on this provider.
	claims, err := s.verifier.Verify(req.UploadToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid upload_token: "+err.Error())
		return
	}
	if claims.Type != "upload" {
		writeError(w, http.StatusForbidden, "token type must be upload")
		return
	}
	if claims.MerkleRoot != req.MerkleRoot {
		writeError(w, http.StatusForbidden, "token merkle mismatch")
		return
	}

	// Pull from the source provider's /download endpoint using the
	// download_token. The source is a peer provider; the download_token
	// was issued by the same coord for this merkle. The source streams its
	// response (store.StreamTo), so we stream it straight into PutStream and
	// never buffer the whole replica in RAM — essential for RF=3 of
	// multi-GB objects, where a buffering receiver would OOM and silently
	// cap durable replication at RAM ÷ concurrency.
	resp, err := openSource(req.SourceURL, req.MerkleRoot, req.DownloadToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "fetch source: "+err.Error())
		return
	}
	defer resp.Body.Close()

	// PutStream verifies the merkle root at close, so a corrupt or wrong-root
	// replica from the source is rejected here instead of being stored and
	// later failing challenges. Treat a mismatch as a bad upstream (502) so
	// the coord can pick another source.
	size, err := s.store.PutStream(req.MerkleRoot, resp.Body)
	if err != nil {
		if errors.Is(err, store.ErrMerkleMismatch) {
			writeError(w, http.StatusBadGateway,
				"source bytes do not hash to merkle root "+req.MerkleRoot)
			return
		}
		writeError(w, http.StatusInternalServerError, "store: "+err.Error())
		return
	}

	// Retention-authority Phase 1: replication targets populate the
	// ownership file identically to a client-driven primary upload when
	// the coord-issued upload token carries both customer pubkeys. See
	// docs/retention_authority_design.md §6.1. Legacy-account
	// replications (token lacks owner_sig_pubkey) skip the write per §9.2.
	if claims.OwnerPubkey != "" && claims.OwnerSigPubkey != "" {
		own := store.Ownership{
			OwnerPubkey:    claims.OwnerPubkey,
			OwnerSigPubkey: claims.OwnerSigPubkey,
			ReceivedAt:     time.Now().UTC(),
		}
		if err := s.store.PutOwnership(req.MerkleRoot, own); err != nil {
			if !errors.Is(err, store.ErrOwnershipExists) {
				writeError(w, http.StatusInternalServerError, "store ownership: "+err.Error())
				return
			}
		}
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"merkle_root": req.MerkleRoot,
		"size_bytes":  size,
	})
}

// openSource issues the GET to the source provider's /download endpoint and
// returns the live response for streaming. The caller owns resp.Body.Close().
// On a non-200 the body is drained and closed so the connection can be reused.
func openSource(sourceAddr, merkle, token string) (*http.Response, error) {
	url := fmt.Sprintf("%s/download/%s", sourceAddr, merkle)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("source returned %d", resp.StatusCode)
	}
	return resp, nil
}
