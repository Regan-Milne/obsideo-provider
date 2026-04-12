package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	providerTypes "github.com/Regan-Milne/obsideo-provider/types"
	"github.com/rs/zerolog/log"
)

type replicateRequest struct {
	SourceURL     string `json:"source_url"`     // base URL of the source provider
	MerkleRoot    string `json:"merkle_root"`    // hex
	Owner         string `json:"owner"`
	Start         int64  `json:"start"`
	ChunkSize     int64  `json:"chunk_size"`
	ProofType     int64  `json:"proof_type"`
	UploadToken   string `json:"upload_token"`   // token for storing on this provider
	DownloadToken string `json:"download_token"` // token for fetching from source provider
}

// handleReplicate downloads a file from another provider and stores it locally.
// Called by the coordinator's replicator.
//
// POST /replicate
// Body: replicateRequest JSON
func (s *Server) handleReplicate(w http.ResponseWriter, r *http.Request) {
	var req replicateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	if req.SourceURL == "" || req.MerkleRoot == "" || req.UploadToken == "" {
		writeErr(w, http.StatusBadRequest, "source_url, merkle_root, and upload_token required")
		return
	}
	if req.ChunkSize <= 0 {
		req.ChunkSize = 10240
	}

	// Validate the upload token so we know the coordinator authorized this replication.
	claims, err := s.ver.Verify(req.UploadToken)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid upload_token: "+err.Error())
		return
	}
	if claims.Type != "upload" {
		writeErr(w, http.StatusForbidden, "token type must be upload")
		return
	}
	if claims.MerkleRoot != req.MerkleRoot {
		writeErr(w, http.StatusForbidden, "token merkle mismatch")
		return
	}

	merkleBytes, err := hex.DecodeString(req.MerkleRoot)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle_root hex")
		return
	}

	// Download the file from the source provider.
	srcURL := fmt.Sprintf("%s/download/%s", req.SourceURL, req.MerkleRoot)
	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, srcURL, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "build source request failed")
		return
	}
	// Use download token if provided, fall back to upload token for backward compat.
	dlToken := req.DownloadToken
	if dlToken == "" {
		dlToken = req.UploadToken
	}
	httpReq.Header.Set("Authorization", "Bearer "+dlToken)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		log.Error().Err(err).Str("src", srcURL).Msg("replicate download failed")
		writeErr(w, http.StatusBadGateway, "download from source failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeErr(w, http.StatusBadGateway, fmt.Sprintf("source returned %d", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "read source body failed")
		return
	}

	owner := req.Owner
	if owner == "" {
		owner = claims.AccountID
	}

	reader := providerTypes.NewBytesSeeker(body)
	size, err := s.fs.WriteFile(reader, merkleBytes, owner, req.Start, req.ChunkSize, req.ProofType)
	if err != nil {
		log.Error().Err(err).Str("merkle", req.MerkleRoot).Msg("replicate write failed")
		writeErr(w, http.StatusInternalServerError, "write failed: "+err.Error())
		return
	}

	log.Info().Str("merkle", req.MerkleRoot).Int("size", size).Str("src", req.SourceURL).Msg("replication complete")
	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_root": req.MerkleRoot,
		"size_bytes":  size,
	})
}
