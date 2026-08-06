package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/tokens"
)

// Range-download tests. The download handler serves well-formed absolute
// single ranges ("bytes=A-B", "bytes=A-") with 206 so ranged S3 GETs relayed
// by the s3-gateway cost O(range length) upstream; every other Range shape
// (absent, suffix, multi-range, malformed) keeps the legacy whole-object 200
// so the gateway's status-based capability detection keeps working across
// the mixed v1-1/v1-2 fleet.
//
// The store keeps objects as flat files — its chunk index exists only for
// challenge proofs — but the boundary-spanning cases below pin that range
// serving stays byte-exact across chunk-index boundaries if the storage
// layout ever changes.

const (
	dlRangeObjectSize = 100
	dlRangeChunkSize  = 16 // small so ranges can span chunk-index boundaries
)

// newDownloadRangeServer stores a non-repeating test object and returns the
// server, its bytes, and a valid download token for it.
func newDownloadRangeServer(t *testing.T) (*Server, []byte, string, string) {
	t.Helper()
	srv, priv := newTestServerWithVerifier(t)

	merkle := strings.Repeat("d", 64)
	data := make([]byte, dlRangeObjectSize)
	for i := range data {
		data[i] = byte(i*7 + 3) // non-repeating mod 256: shifted windows never compare equal
	}
	if err := srv.store.Put(merkle, data, dlRangeChunkSize); err != nil {
		t.Fatalf("store.Put: %v", err)
	}

	token := signTestToken(t, priv, tokens.Claims{
		Type:       "download",
		MerkleRoot: merkle,
		AccountID:  "test-account",
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(time.Minute).Unix(),
	})
	return srv, data, merkle, token
}

func downloadWithRange(t *testing.T, srv *Server, merkle, token, rangeHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/download/"+merkle, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// check206 asserts a 206 carrying exactly data[start:end+1] with matching
// Content-Range and Content-Length.
func check206(t *testing.T, rec *httptest.ResponseRecorder, data []byte, start, end int) {
	t.Helper()
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206; body = %s", rec.Code, rec.Body.String())
	}
	if got, want := rec.Body.String(), string(data[start:end+1]); got != want {
		t.Errorf("body mismatch for window %d-%d (%d bytes, want %d)", start, end, len(got), len(want))
	}
	wantCR := fmt.Sprintf("bytes %d-%d/%d", start, end, len(data))
	if cr := rec.Header().Get("Content-Range"); cr != wantCR {
		t.Errorf("Content-Range = %q, want %q", cr, wantCR)
	}
	if cl := rec.Header().Get("Content-Length"); cl != fmt.Sprint(end-start+1) {
		t.Errorf("Content-Length = %q, want %d", cl, end-start+1)
	}
}

// check200Full asserts the legacy whole-object 200 shape.
func check200Full(t *testing.T, rec *httptest.ResponseRecorder, data []byte) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(data) {
		t.Errorf("body = %d bytes, want the whole object (%d bytes)", rec.Body.Len(), len(data))
	}
	if cr := rec.Header().Get("Content-Range"); cr != "" {
		t.Errorf("whole-object 200 must not carry Content-Range; got %q", cr)
	}
}

func TestDownloadFullObjectUnchanged(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	rec := downloadWithRange(t, srv, merkle, token, "")
	check200Full(t, rec, data)
}

func TestDownloadRangeWithinFirstChunk(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	rec := downloadWithRange(t, srv, merkle, token, "bytes=2-9")
	check206(t, rec, data, 2, 9)
}

func TestDownloadRangeSpansChunkBoundary(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	// Spans the dlRangeChunkSize (16) chunk-index boundary.
	rec := downloadWithRange(t, srv, merkle, token, "bytes=12-19")
	check206(t, rec, data, 12, 19)
}

func TestDownloadRangeMidObject(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	rec := downloadWithRange(t, srv, merkle, token, "bytes=48-63")
	check206(t, rec, data, 48, 63)
}

func TestDownloadRangeOpenEnded(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	rec := downloadWithRange(t, srv, merkle, token, "bytes=90-")
	check206(t, rec, data, 90, dlRangeObjectSize-1)
}

func TestDownloadRangeEndClamped(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	rec := downloadWithRange(t, srv, merkle, token, "bytes=95-500")
	check206(t, rec, data, 95, dlRangeObjectSize-1)
}

func TestDownloadRangeStartPastEOFIs416(t *testing.T) {
	srv, _, merkle, token := newDownloadRangeServer(t)
	for _, rng := range []string{"bytes=100-", "bytes=200-300"} {
		rec := downloadWithRange(t, srv, merkle, token, rng)
		if rec.Code != http.StatusRequestedRangeNotSatisfiable {
			t.Errorf("%q: status = %d, want 416", rng, rec.Code)
		}
		wantCR := fmt.Sprintf("bytes */%d", dlRangeObjectSize)
		if cr := rec.Header().Get("Content-Range"); cr != wantCR {
			t.Errorf("%q: Content-Range = %q, want %q", rng, cr, wantCR)
		}
	}
}

// Suffix and multi-range shapes are never emitted by the s3-gateway (it
// resolves them to absolute windows first); the provider deliberately falls
// back to the always-correct whole-object 200 for them.
func TestDownloadRangeNonForwardedShapesServeFullObject(t *testing.T) {
	srv, data, merkle, token := newDownloadRangeServer(t)
	for _, rng := range []string{"bytes=-10", "bytes=0-1,5-6", "items=0-5", "bytes=abc-def", "bytes=5"} {
		rec := downloadWithRange(t, srv, merkle, token, rng)
		t.Run(rng, func(t *testing.T) { check200Full(t, rec, data) })
	}
}

func TestParseSingleByteRange(t *testing.T) {
	cases := []struct {
		name   string
		header string
		start  int64
		end    int64
		ok     bool
	}{
		{"absent", "", 0, 0, false},
		{"non-bytes unit", "items=0-5", 0, 0, false},
		{"multi-range", "bytes=0-1,3-4", 0, 0, false},
		{"no dash", "bytes=5", 0, 0, false},
		{"empty spec", "bytes=-", 0, 0, false},
		{"suffix not supported", "bytes=-25", 0, 0, false},
		{"closed", "bytes=10-19", 10, 19, true},
		{"single byte", "bytes=0-0", 0, 0, true},
		{"open ended", "bytes=40-", 40, -1, true},
		{"inverted", "bytes=20-10", 0, 0, false},
		{"negative start", "bytes=--5-10", 0, 0, false},
		{"garbage", "bytes=abc-def", 0, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start, end, ok := parseSingleByteRange(c.header)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && (start != c.start || end != c.end) {
				t.Fatalf("(start,end) = (%d,%d), want (%d,%d)", start, end, c.start, c.end)
			}
		})
	}
}
