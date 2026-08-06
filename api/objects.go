package api

import (
	"bytes"
	"io"
	"net/http"
)

// handleDelete and handleList used to live here, serving
// DELETE /objects/{merkle} and GET /list. Both were unauthenticated and
// both are gone; see the "DELIBERATELY ABSENT" note in server.go for
// why, and delete.go for the signature-gated erase path that replaces
// the former. Do not reintroduce an unsigned erase or an unauthenticated
// enumeration endpoint here.

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// newBytesReader wraps a byte slice in an io.Reader for use as an HTTP request body.
func newBytesReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}
