package api

import (
	"encoding/hex"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// handleDownload streams the file identified by merkle root.
//
// GET /download/{merkle}
//   Authorization: Bearer <download_token>
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
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
	if claims.Type != "download" {
		writeErr(w, http.StatusForbidden, "token type must be download")
		return
	}
	if claims.MerkleRoot != merkleHex {
		writeErr(w, http.StatusForbidden, "token merkle mismatch")
		return
	}

	merkleBytes, err := hex.DecodeString(merkleHex)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle hex")
		return
	}

	rc, err := s.fs.GetFileData(merkleBytes)
	if err != nil {
		log.Error().Err(err).Str("merkle", merkleHex).Msg("download failed")
		writeErr(w, http.StatusNotFound, "object not found")
		return
	}
	defer rc.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, rc); err != nil {
		log.Warn().Err(err).Str("merkle", merkleHex).Msg("stream interrupted")
	}
}
