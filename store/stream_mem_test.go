package store

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
)

// patternReader emits patternBytes(total) lazily, without ever materializing
// the object in memory. This lets the flat-memory test stream an object far
// larger than we'd want to allocate, so any size-proportional buffering in
// PutStream shows up as heap growth.
type patternReader struct {
	total int64
	pos   int64
}

func (r *patternReader) Read(p []byte) (int, error) {
	if r.pos >= r.total {
		return 0, io.EOF
	}
	n := int64(len(p))
	if r.pos+n > r.total {
		n = r.total - r.pos
	}
	for i := int64(0); i < n; i++ {
		p[i] = byte((r.pos + i) % 251)
	}
	r.pos += n
	return int(n), nil
}

// TestPutStream_FlatMemory streams a large object through a generating reader
// and asserts heap growth stays far below the object size. A regression that
// reintroduced io.ReadAll / full-buffer assembly would push HeapInuse to
// ~objectSize; the only size-dependent state PutStream legitimately keeps is
// the slice of per-chunk hash strings (~64 bytes per MiB), so the real growth
// is a few hundred KB for this size. Bound is generous to avoid flakiness
// from GC timing while still catching a full-buffer regression by an order of
// magnitude.
func TestPutStream_FlatMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping flat-memory test in -short mode")
	}
	st := newTestStore(t)
	const objectSize = 512 * 1048576 // 512 MiB
	// Precompute the expected root from the same lazy pattern (BuildMerkleTree
	// needs the bytes, but only for the root reference — we generate them once
	// here, then discard, so the measured section below never holds them).
	root := func() string {
		data := make([]byte, objectSize)
		for i := range data {
			data[i] = byte(i % 251)
		}
		r, _, err := BuildMerkleTree(data)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}()
	runtime.GC()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	n, err := st.PutStream(root, &patternReader{total: objectSize})
	if err != nil {
		t.Fatalf("PutStream: %v", err)
	}
	if n != objectSize {
		t.Fatalf("size = %d, want %d", n, objectSize)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	// HeapInuse delta should be a tiny fraction of the object size.
	grew := int64(after.HeapInuse) - int64(before.HeapInuse)
	if grew < 0 {
		grew = 0
	}
	limit := int64(objectSize) / 8 // 64 MiB ceiling for a 512 MiB object
	t.Logf("heap grew %d bytes streaming a %d-byte object (limit %d)", grew, objectSize, limit)
	if grew > limit {
		t.Errorf("heap grew %d bytes for a %d-byte object — buffering regression? (limit %d)",
			grew, objectSize, limit)
	}
}

// TestPutStream_Concurrent proves the ingest path is safe under concurrent
// large objects (the real failure mode the old buffering had: RAM ÷
// concurrency). Each goroutine ingests a distinct object; all must land
// byte-exact. Run under -race to catch any shared-state bug; PutStream and
// TreeBuilder hold no shared state, so this should be clean.
func TestPutStream_Concurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping concurrent test in -short mode")
	}
	st := newTestStore(t)
	const workers = 8

	// Distinct object per worker so roots differ.
	objects := make([][]byte, workers)
	roots := make([]string, workers)
	for i := 0; i < workers; i++ {
		// Vary size and a salt byte so each object has a unique root.
		data := patternBytes(1048576 + i*101 + 1)
		data[0] = byte(i) // salt: distinct first byte -> distinct root
		root, _, err := BuildMerkleTree(data)
		if err != nil {
			t.Fatal(err)
		}
		objects[i], roots[i] = data, root
	}

	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := st.PutStream(roots[i], bytes.NewReader(objects[i])); err != nil {
				errs[i] = fmt.Errorf("worker %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		got, err := st.Get(roots[i])
		if err != nil || !bytes.Equal(got, objects[i]) {
			t.Errorf("worker %d object not byte-exact: err=%v", i, err)
		}
	}
	if n := countObjTemps(t, st); n != 0 {
		t.Errorf("%d temp file(s) leaked after concurrent ingest", n)
	}
}

// TestPutStream_SizeLadder walks a ladder of sizes spanning the chunk
// boundary and several power-of-2 tree-padding cases, verifying byte-exact
// storage and that the stored root is addressable at each rung.
func TestPutStream_SizeLadder(t *testing.T) {
	sizes := []int{
		1, 1023, 1048575, 1048576, 1048577,
		2 * 1048576, 3 * 1048576, 5*1048576 + 12345, 17 * 1048576,
	}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%dB", sz), func(t *testing.T) {
			st := newTestStore(t)
			data := patternBytes(sz)
			root, _, err := BuildMerkleTree(data)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.PutStream(root, bytes.NewReader(data)); err != nil {
				t.Fatalf("PutStream(%d): %v", sz, err)
			}
			got, err := st.Get(root)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("size %d not byte-exact: err=%v", sz, err)
			}
		})
	}
}
