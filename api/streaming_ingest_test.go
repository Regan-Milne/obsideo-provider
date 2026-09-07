package api

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/store"
	"github.com/obsideo/obsideo-provider/tokens"
)

// Streaming-ingest characterization + behavior tests for stage 3 (provider
// streaming ingest). These pin the properties the rewrite must preserve
// (byte-exact storage, correct 1 MiB index, the common small-file path) and
// the new property it adds (verify-merkle-root-at-close: reject on mismatch,
// store nothing). All three ingest paths are covered: single-shot upload,
// chunked finalize, and replication receive.

func uploadTokenFor(t *testing.T, priv ed25519.PrivateKey, merkle string) string {
	t.Helper()
	return signTestToken(t, priv, tokens.Claims{
		Type:       "upload",
		MerkleRoot: merkle,
		ProviderID: "test-provider",
		AccountID:  "acct",
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(5 * time.Minute).Unix(),
	})
}

// --- single-shot upload ---

func TestUpload_Streaming_ByteExactAndIndexed(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	// 2 chunks + ragged tail: real multi-chunk object.
	payload := patternBytesAPI(2*1048576 + 333)
	merkle := merkleRootOf(t, payload)
	tok := uploadTokenFor(t, priv, merkle)

	rec := uploadTo(t, srv, merkle, tok, payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: code=%d body=%s", rec.Code, rec.Body.String())
	}

	got, err := srv.store.Get(merkle)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("stored bytes not byte-exact (%d vs %d)", len(got), len(payload))
	}
	idx, err := srv.store.GetIndex(merkle)
	if err != nil {
		t.Fatalf("GetIndex: %v", err)
	}
	if idx.ChunkSize != store.DefaultChunkSize || idx.TotalChunks != 3 {
		t.Errorf("index chunk_size=%d total=%d, want %d/3", idx.ChunkSize, idx.TotalChunks, store.DefaultChunkSize)
	}
}

// TestUpload_Streaming_SmallFile is the common small-file path: a sub-1 MiB single
// chunk. The most common real upload shape; must keep working unchanged.
func TestUpload_Streaming_SmallFile(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	payload := patternBytesAPI(1500) // ~1.5 KB image-thumbnail shape
	merkle := merkleRootOf(t, payload)
	tok := uploadTokenFor(t, priv, merkle)

	rec := uploadTo(t, srv, merkle, tok, payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("small-file upload: code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, err := srv.store.Get(merkle)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("small file not stored byte-exact: err=%v", err)
	}
	idx, _ := srv.store.GetIndex(merkle)
	if idx.TotalChunks != 1 {
		t.Errorf("small file total_chunks=%d, want 1", idx.TotalChunks)
	}
}

func TestUpload_Streaming_WrongRoot_422_NothingStored(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	// Token authorizes a real root (of some OTHER bytes); we upload bytes
	// that hash to something else. The handler must reject at close.
	otherBytes := patternBytesAPI(4096)
	claimedRoot := merkleRootOf(t, otherBytes)
	wrongPayload := patternBytesAPI(5000) // hashes to a different root
	if merkleRootOf(t, wrongPayload) == claimedRoot {
		t.Fatal("test setup: payloads collided")
	}
	tok := uploadTokenFor(t, priv, claimedRoot)

	rec := uploadTo(t, srv, claimedRoot, tok, wrongPayload)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong-root upload: code=%d body=%s, want 422", rec.Code, rec.Body.String())
	}
	if _, err := srv.store.Get(claimedRoot); err == nil {
		t.Error("object was stored despite root mismatch")
	}
}

// --- chunked upload (finalize assembly) ---

func uploadChunk(t *testing.T, srv *Server, merkle, tok string, index, total int, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/upload/%s/chunk?index=%d&total=%d", merkle, index, total)
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func finalize(t *testing.T, srv *Server, merkle, tok string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload/"+merkle+"/finalize", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestChunkedUpload_Streaming_RoundTrip(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	// Object larger than one transport chunk; transport chunking (here 5 MB
	// shape, simplified to 3 parts) is independent of the 1 MiB merkle.
	payload := patternBytesAPI(3*1048576 + 777)
	merkle := merkleRootOf(t, payload)
	tok := uploadTokenFor(t, priv, merkle)

	const transport = 1_400_000 // arbitrary transport chunk size != 1 MiB
	parts := 0
	for off := 0; off < len(payload); off += transport {
		end := off + transport
		if end > len(payload) {
			end = len(payload)
		}
		parts++
	}
	idx := 0
	for off := 0; off < len(payload); off += transport {
		end := off + transport
		if end > len(payload) {
			end = len(payload)
		}
		rec := uploadChunk(t, srv, merkle, tok, idx, parts, payload[off:end])
		if rec.Code != http.StatusOK {
			t.Fatalf("chunk %d: code=%d body=%s", idx, rec.Code, rec.Body.String())
		}
		idx++
	}

	rec := finalize(t, srv, merkle, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("finalize: code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, err := srv.store.Get(merkle)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("chunked object not byte-exact: err=%v", err)
	}
}

func TestChunkedUpload_TamperedAssembly_422_StagingDropped(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	payload := patternBytesAPI(2 * 1048576)
	merkle := merkleRootOf(t, payload)
	tok := uploadTokenFor(t, priv, merkle)

	// Upload two chunks, but corrupt the second so the assembled bytes don't
	// hash to merkle.
	half := len(payload) / 2
	if rec := uploadChunk(t, srv, merkle, tok, 0, 2, payload[:half]); rec.Code != http.StatusOK {
		t.Fatalf("chunk 0: %d", rec.Code)
	}
	corrupt := append([]byte(nil), payload[half:]...)
	corrupt[0] ^= 0xFF
	if rec := uploadChunk(t, srv, merkle, tok, 1, 2, corrupt); rec.Code != http.StatusOK {
		t.Fatalf("chunk 1: %d", rec.Code)
	}

	rec := finalize(t, srv, merkle, tok)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered finalize: code=%d body=%s, want 422", rec.Code, rec.Body.String())
	}
	if _, err := srv.store.Get(merkle); err == nil {
		t.Error("object stored despite tampered assembly")
	}
	// Staging must be dropped on mismatch so a resume starts clean.
	st := finalize(t, srv, merkle, tok) // a re-finalize now finds no staged chunks
	if st.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (no staged chunks) after staging drop, got %d", st.Code)
	}
}

// --- replication receive ---

func TestReplicate_Streaming_RoundTrip(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	payload := patternBytesAPI(2*1048576 + 11)
	merkle := merkleRootOf(t, payload)

	// Stand up a source provider that streams the object on /download/{merkle}.
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
	}))
	defer source.Close()

	tok := uploadTokenFor(t, priv, merkle)
	body := fmt.Sprintf(`{"source_url":%q,"merkle_root":%q,"upload_token":%q,"download_token":"dl"}`,
		source.URL, merkle, tok)
	req := httptest.NewRequest(http.MethodPost, "/replicate", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("replicate: code=%d body=%s", rec.Code, rec.Body.String())
	}
	got, err := srv.store.Get(merkle)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("replicated object not byte-exact: err=%v", err)
	}
}

func TestReplicate_SourceCorrupt_502_NothingStored(t *testing.T) {
	srv, priv := newTestServerWithVerifier(t)
	payload := patternBytesAPI(1048576 + 5)
	merkle := merkleRootOf(t, payload)

	// Source serves bytes that do NOT hash to the requested merkle.
	corrupt := append([]byte(nil), payload...)
	corrupt[0] ^= 0xFF
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(corrupt)
	}))
	defer source.Close()

	tok := uploadTokenFor(t, priv, merkle)
	body := fmt.Sprintf(`{"source_url":%q,"merkle_root":%q,"upload_token":%q,"download_token":"dl"}`,
		source.URL, merkle, tok)
	req := httptest.NewRequest(http.MethodPost, "/replicate", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("corrupt-source replicate: code=%d body=%s, want 502", rec.Code, rec.Body.String())
	}
	if _, err := srv.store.Get(merkle); err == nil {
		t.Error("corrupt replica was stored")
	}
}

// patternBytesAPI mirrors the store-package patternBytes for api tests.
func patternBytesAPI(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}
