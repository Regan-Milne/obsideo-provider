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
	if req.ChunkSize <= 0 {
		req.ChunkSize = int64(store.DefaultChunkSize)
	}

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
	// was issued by the same coord for this merkle.
	data, err := fetchFromSource(req.SourceURL, req.MerkleRoot, req.DownloadToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "fetch source: "+err.Error())
		return
	}

	// Store locally using the same path regular uploads take. This writes
	// the object file plus chunk index so challenges can be answered.
	if err := s.store.Put(req.MerkleRoot, data, int(req.ChunkSize)); err != nil {
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
		"size_bytes":  len(data),
	})
}

func fetchFromSource(sourceAddr, merkle, token string) ([]byte, error) {
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
