package store

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestStore returns a Store rooted at a temp dir.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return st
}

// countObjTemps returns how many ".tmp-stream-*" leftovers exist in objects/.
// Any nonzero count after a completed PutStream is a temp-file leak.
func countObjTemps(t *testing.T, s *Store) int {
	t.Helper()
	entries, err := os.ReadDir(s.objDir)
	if err != nil {
		t.Fatalf("read objDir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), objTempPrefix) {
			n++
		}
	}
	return n
}

func TestPutStream_RoundTrip_ByteExact(t *testing.T) {
	st := newTestStore(t)
	// Multi-chunk, ragged tail: exercises the streaming re-chunking.
	data := patternBytes(3*1048576 + 4321)
	root, wantHashes, err := BuildMerkleTree(data)
	if err != nil {
		t.Fatal(err)
	}

	size, err := st.PutStream(root, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	if size != int64(len(data)) {
		t.Errorf("size = %d, want %d", size, len(data))
	}

	got, err := st.Get(root)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("stored bytes not byte-exact (got %d bytes, want %d)", len(got), len(data))
	}

	idx, err := st.GetIndex(root)
	if err != nil {
		t.Fatalf("GetIndex: %v", err)
	}
	if idx.ChunkSize != DefaultChunkSize {
		t.Errorf("index chunk_size = %d, want %d", idx.ChunkSize, DefaultChunkSize)
	}
	if idx.TotalChunks != len(wantHashes) {
		t.Errorf("index total_chunks = %d, want %d", idx.TotalChunks, len(wantHashes))
	}
	for i := range wantHashes {
		if idx.ChunkHashes[i] != wantHashes[i] {
			t.Errorf("index chunk hash %d mismatch", i)
		}
	}
	if countObjTemps(t, st) != 0 {
		t.Errorf("temp file leaked after successful PutStream")
	}
}

func TestPutStream_Mismatch_RejectsAndStoresNothing(t *testing.T) {
	st := newTestStore(t)
	data := patternBytes(2*1048576 + 99)
	realRoot, _, err := BuildMerkleTree(data)
	if err != nil {
		t.Fatal(err)
	}
	// Claim a different (but well-formed) root than the bytes produce.
	wrongRoot := strings.Repeat("0", 128)
	if wrongRoot == realRoot {
		t.Fatal("test setup: wrong root collided with real root")
	}

	_, err = st.PutStream(wrongRoot, bytes.NewReader(data))
	if !errors.Is(err, ErrMerkleMismatch) {
		t.Fatalf("PutStream with wrong root: got err %v, want ErrMerkleMismatch", err)
	}

	// Nothing committed under EITHER root.
	if _, err := st.Get(wrongRoot); !errors.Is(err, ErrNotFound) {
		t.Errorf("object stored under wrong root despite mismatch: %v", err)
	}
	if _, err := st.GetIndex(wrongRoot); !errors.Is(err, ErrNotFound) {
		t.Errorf("index stored under wrong root despite mismatch: %v", err)
	}
	if _, err := st.Get(realRoot); !errors.Is(err, ErrNotFound) {
		t.Errorf("object stored under real root despite mismatch: %v", err)
	}
	// And no temp leftover.
	if n := countObjTemps(t, st); n != 0 {
		t.Errorf("%d temp file(s) leaked after rejected PutStream", n)
	}
}

func TestPutStream_Idempotent(t *testing.T) {
	st := newTestStore(t)
	data := patternBytes(1048576 + 7)
	root, _, err := BuildMerkleTree(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutStream(root, bytes.NewReader(data)); err != nil {
		t.Fatalf("first PutStream: %v", err)
	}
	if _, err := st.PutStream(root, bytes.NewReader(data)); err != nil {
		t.Fatalf("second PutStream (idempotent re-put): %v", err)
	}
	got, err := st.Get(root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("bytes not intact after idempotent re-put")
	}
	if countObjTemps(t, st) != 0 {
		t.Error("temp file leaked across idempotent re-put")
	}
}

func TestPutStream_Empty_Rejected(t *testing.T) {
	st := newTestStore(t)
	root := strings.Repeat("a", 128)
	if _, err := st.PutStream(root, bytes.NewReader(nil)); err == nil {
		t.Fatal("PutStream of empty body should error (empty object has no network identity)")
	}
	if _, err := st.Get(root); !errors.Is(err, ErrNotFound) {
		t.Error("empty upload stored an object")
	}
	if countObjTemps(t, st) != 0 {
		t.Error("temp file leaked after empty-body rejection")
	}
}

// TestPutStream_LargeObject proves correctness at a size well past any chunk
// boundary count without the test itself buffering a second copy for
// comparison: we verify by content address (the root the bytes hashed to ==
// the root PutStream verified) plus the on-disk size. True RSS-flatness is
// validated against the running binary in stage 2.
func TestPutStream_LargeObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large-object test in -short mode")
	}
	st := newTestStore(t)
	const size = 96 * 1048576 // 96 MiB, 96 chunks
	data := patternBytes(size)
	root, _, err := BuildMerkleTree(data)
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.PutStream(root, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PutStream(96MiB): %v", err)
	}
	if n != int64(size) {
		t.Errorf("size = %d, want %d", n, size)
	}
	got, err := st.Get(root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Error("96MiB object not byte-exact after streaming ingest")
	}
}

func TestSweepStaleObjectTemps(t *testing.T) {
	st := newTestStore(t)

	// A real object (hex-named) must never be swept.
	data := patternBytes(1024)
	root, _, _ := BuildMerkleTree(data)
	if _, err := st.PutStream(root, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}

	// An old temp orphan (simulating a kill mid-stream).
	oldTmp, err := os.CreateTemp(st.objDir, objTempPrefix)
	if err != nil {
		t.Fatal(err)
	}
	oldTmp.Close()
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(oldTmp.Name(), old, old); err != nil {
		t.Fatal(err)
	}

	// A fresh temp orphan (an upload that might still be in flight).
	freshTmp, err := os.CreateTemp(st.objDir, objTempPrefix)
	if err != nil {
		t.Fatal(err)
	}
	freshTmp.Close()

	cleaned, err := st.SweepStaleObjectTemps(time.Hour)
	if err != nil {
		t.Fatalf("SweepStaleObjectTemps: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("cleaned = %d, want 1 (only the >1h-old orphan)", cleaned)
	}
	if _, err := os.Stat(oldTmp.Name()); !os.IsNotExist(err) {
		t.Error("old temp orphan was not removed")
	}
	if _, err := os.Stat(freshTmp.Name()); err != nil {
		t.Error("fresh temp orphan was incorrectly removed")
	}
	if _, err := st.Get(root); err != nil {
		t.Error("real object was disturbed by the sweep")
	}
}
