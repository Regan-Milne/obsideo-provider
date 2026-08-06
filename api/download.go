package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/obsideo/obsideo-provider/store"
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

	// Single-range requests are served with 206 so ranged S3 GETs relayed by
	// the s3-gateway cost O(range length) upstream instead of O(object size).
	// Anything that is not a well-formed absolute single range falls through
	// to the legacy whole-object 200 — the gateway detects range support via
	// the 206 status, never via provider version strings, so old and new
	// providers can coexist behind one coordinator.
	if start, end, ok := parseSingleByteRange(r.Header.Get("Range")); ok {
		s.serveRange(w, merkle, start, end)
		return
	}

	if err := s.store.StreamTo(merkle, w); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Header already sent if StreamTo failed partway; best we can do is close.
			return
		}
		return
	}
}

// parseSingleByteRange parses "bytes=A-B" or "bytes=A-" — absolute single
// ranges only. ok=false means "serve the whole object": an absent header,
// non-bytes units, the suffix form ("bytes=-N"), multi-range specs, and
// malformed specs all keep the legacy full-stream path (always correct,
// just not partial). The s3-gateway resolves client ranges to absolute
// closed windows against the coordinator-registered size before forwarding,
// so this narrow grammar covers the production caller. end == -1 means
// "through EOF".
func parseSingleByteRange(header string) (start, end int64, ok bool) {
	spec, found := strings.CutPrefix(header, "bytes=")
	if !found || strings.Contains(spec, ",") {
		return 0, 0, false
	}
	first, last, dash := strings.Cut(spec, "-")
	if !dash || first == "" {
		return 0, 0, false
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false
	}
	if last == "" {
		return start, -1, true
	}
	end, err = strconv.ParseInt(last, 10, 64)
	if err != nil || end < start {
		return 0, 0, false
	}
	return start, end, true
}

// serveRange streams object bytes [start, end] (end == -1 meaning EOF,
// end past EOF clamped) with 206 + Content-Range. A start at or past EOF
// is 416 with "Content-Range: bytes */<size>" per RFC 9110 — the gateway
// maps that to a 502 exactly like the short-stream failure it replaces.
// A missing object mirrors the legacy whole-object path's not-found shape
// (return with nothing written) rather than inventing a new one.
func (s *Server) serveRange(w http.ResponseWriter, merkle string, start, end int64) {
	f, err := s.store.OpenObject(merkle)
	if err != nil {
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return
	}
	size := fi.Size()

	if start >= size {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		writeError(w, http.StatusRequestedRangeNotSatisfiable, "range start past end of object")
		return
	}
	if end < 0 || end > size-1 {
		end = size - 1
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		writeError(w, http.StatusInternalServerError, "seek failed")
		return
	}

	length := end - start + 1
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)
	// Past the status line now — an error here can only truncate, like the
	// whole-object path.
	_, _ = io.CopyN(w, f, length)
}
