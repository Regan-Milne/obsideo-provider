package api

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/Regan-Milne/obsideo-provider/config"
	providerTypes "github.com/Regan-Milne/obsideo-provider/types"
	"github.com/rs/zerolog/log"
)

// handleUpload receives a raw file body, verifies the upload token, and stores the file.
//
// POST /upload/{merkle}
//   Authorization: Bearer <upload_token>
//   Query params:
//     owner      - account ID (defaults to token's account_id)
//     start      - int64, defaults to 0
//     chunk_size - int, defaults to config.DefaultChunkSize
//     proof_type - int64, defaults to 0
//   Body: raw file bytes
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	merkleHex := mux.Vars(r)["merkle"]

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
	if claims.Type != "upload" {
		writeErr(w, http.StatusForbidden, "token type must be upload")
		return
	}
	if claims.MerkleRoot != merkleHex {
		writeErr(w, http.StatusForbidden, "token merkle mismatch")
		return
	}
	// Note: we don't validate claims.ProviderID here because the provider doesn't
	// know its coordinator-assigned UUID at startup. Token signature is sufficient proof.

	merkleBytes, err := hex.DecodeString(merkleHex)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle hex")
		return
	}

	owner := r.URL.Query().Get("owner")
	if owner == "" {
		owner = claims.AccountID
	}

	start := int64(0)
	if v := r.URL.Query().Get("start"); v != "" {
		start, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid start")
			return
		}
	}

	chunkSize := int64(config.DefaultChunkSize)
	if v := r.URL.Query().Get("chunk_size"); v != "" {
		chunkSize, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid chunk_size")
			return
		}
	}

	proofType := int64(providerTypes.ProofTypeDefault)
	if v := r.URL.Query().Get("proof_type"); v != "" {
		proofType, err = strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid proof_type")
			return
		}
	}

	declaredLen := r.Header.Get("Content-Length")
	log.Info().
		Str("merkle", merkleHex).
		Str("content_length", declaredLen).
		Int64("chunk_size", chunkSize).
		Msg("upload: reading body")

	// Limit upload body to 5 GB to prevent memory exhaustion.
	const maxUploadBytes = 5 * 1024 * 1024 * 1024 // 5 GB
	limited := http.MaxBytesReader(w, r.Body, maxUploadBytes)

	tRead := time.Now()
	body, err := io.ReadAll(limited)
	readDur := time.Since(tRead)
	if err != nil {
		log.Error().Err(err).Str("merkle", merkleHex).
			Dur("read_dur", readDur).
			Msg("upload: body read error")
		writeErr(w, http.StatusBadRequest, "failed to read body")
		return
	}
	if len(body) == 0 {
		writeErr(w, http.StatusBadRequest, "empty body")
		return
	}
	log.Info().
		Str("merkle", merkleHex).
		Int("body_bytes", len(body)).
		Dur("read_dur", readDur).
		Msg("upload: body read complete")

	tWrite := time.Now()
	reader := providerTypes.NewBytesSeeker(body)
	size, err := s.fs.WriteFile(reader, merkleBytes, owner, start, chunkSize, proofType)
	writeDur := time.Since(tWrite)
	if err != nil {
		log.Error().Err(err).Str("merkle", merkleHex).
			Dur("write_dur", writeDur).
			Msg("upload failed")
		writeErr(w, http.StatusInternalServerError, fmt.Sprintf("write failed: %s", err))
		return
	}

	log.Info().
		Str("merkle", merkleHex).
		Int("size", size).
		Dur("write_dur", writeDur).
		Msg("upload stored")
	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_root": merkleHex,
		"size_bytes":  size,
	})
}
