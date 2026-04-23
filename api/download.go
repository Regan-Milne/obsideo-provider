package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/Regan-Milne/obsideo-provider/store"
)

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
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
	if claims.Type != "download" {
		writeError(w, http.StatusForbidden, "expected download token")
		return
	}
	if claims.MerkleRoot != merkle {
		writeError(w, http.StatusForbidden, "token merkle_root does not match URL")
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	if err := s.store.StreamTo(merkle, w); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Header already sent if StreamTo failed partway; best we can do is close.
			return
		}
		return
	}
}
