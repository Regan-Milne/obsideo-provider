package api

import (
	"encoding/hex"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

// handleDeleteObject removes a stored object.
// Called by the coordinator's GC after confirming no remaining references.
//
// DELETE /objects/{merkle}
func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	merkleHex := mux.Vars(r)["merkle"]

	merkleBytes, err := hex.DecodeString(merkleHex)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid merkle hex")
		return
	}

	// Delete all tree entries for this merkle root regardless of (owner, start).
	// The GC calls this endpoint knowing only the merkle root; it doesn't carry
	// the original owner/start metadata.
	if err := s.fs.DeleteAllForMerkle(merkleBytes); err != nil {
		log.Error().Err(err).Str("merkle", merkleHex).Msg("delete failed")
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Info().Str("merkle", merkleHex).Msg("object deleted")
	w.WriteHeader(http.StatusNoContent)
}

// handleList returns all merkle roots stored on this provider.
// Used by the coordinator's GC to enumerate stored objects.
//
// GET /list
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	merkles, _, _, err := s.fs.ListFiles()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	hexRoots := make([]string, len(merkles))
	for i, m := range merkles {
		hexRoots[i] = hex.EncodeToString(m)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_roots": hexRoots,
		"count":        len(hexRoots),
	})
}
