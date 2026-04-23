package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Regan-Milne/obsideo-provider/store"
)

type challengeRequest struct {
	ChallengeID string `json:"challenge_id"`
	Merkle      string `json:"merkle"` // coordinator sends "merkle", not "merkle_root"
	ChunkIndex  int    `json:"chunk_index"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expires_at"` // Unix timestamp
}

type challengeResponse struct {
	ChallengeID     string `json:"challenge_id"`
	ChunkHash       string `json:"chunk_hash"`       // hex sha256(fmt.Sprintf("%d%x", idx, chunk))
	TotalChunkCount int    `json:"total_chunk_count"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}

	idx, err := s.store.GetIndex(req.Merkle)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "object not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.ChunkIndex < 0 || req.ChunkIndex >= idx.TotalChunks {
		writeError(w, http.StatusBadRequest, "chunk_index out of range")
		return
	}

	writeJSON(w, http.StatusOK, challengeResponse{
		ChallengeID:     req.ChallengeID,
		ChunkHash:       idx.ChunkHashes[req.ChunkIndex],
		TotalChunkCount: idx.TotalChunks,
	})
}
