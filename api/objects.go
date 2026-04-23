package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	merkle := chi.URLParam(r, "merkle")
	if err := s.store.Delete(merkle); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	roots, err := s.store.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"merkle_roots": roots,
		"count":        len(roots),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// newBytesReader wraps a byte slice in an io.Reader for use as an HTTP request body.
func newBytesReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}
