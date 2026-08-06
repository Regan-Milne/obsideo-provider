package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// objTempPrefix is the temp-file prefix PutStream uses inside objects/.
// Kept in sync with the os.CreateTemp pattern below so the startup sweep can
// recognize its own orphans.
const objTempPrefix = ".tmp-stream-"

// ErrMerkleMismatch is returned by PutStream when the merkle root computed
// from the streamed bytes does not equal the expected root (the URL/token
// merkle the caller passed). The object is NOT committed: content addressing
// means the stored bytes must hash to their name, so a mismatch is a rejected
// upload, never a stored object. Callers map this to a 4xx (client/content
// error), not a 5xx.
var ErrMerkleMismatch = errors.New("computed merkle root does not match expected root")

// streamCopyBufSize is the io.Copy buffer used to move bytes from the request
// body to disk. 1 MiB matches the merkle chunk size and keeps syscall count
// reasonable for multi-GB objects while holding memory flat.
const streamCopyBufSize = 1 << 20

// PutStream ingests r into the object identified by expectedRoot using
// bounded memory, replacing the io.ReadAll + Put(buildIndex) path that made
// the large-object ceiling RAM ÷ concurrency.
//
// Bytes are streamed to a temp file on the objects/ disk while a TreeBuilder
// hashes the frontier incrementally (1 MiB chunks). At EOF the merkle root is
// computed from that single pass and verified against expectedRoot:
//
//   - mismatch  -> the temp file is discarded and ErrMerkleMismatch returned;
//     nothing is committed (content-addressing integrity).
//   - match     -> the chunk index is written from the hashes produced by the
//     same pass (no second full-object hash pass), then the object is
//     atomically renamed into place. The object only becomes addressable in
//     objects/ after its bytes are verified and its index is on disk.
//
// Memory is flat regardless of object size (the gateway's streaming PUT and
// this provider's streaming download, store.StreamTo, use the same shape).
// Returns the number of bytes ingested.
//
// On any error the partial temp file is removed; a process kill mid-stream
// can still leave a ".tmp-stream-*" orphan in objects/ — those are swept at
// startup by SweepStaleObjectTemps and are never counted as objects (List /
// UsedBytes skip non-hex names).
func (s *Store) PutStream(expectedRoot string, r io.Reader) (size int64, err error) {
	tmp, err := os.CreateTemp(s.objDir, objTempPrefix)
	if err != nil {
		return 0, fmt.Errorf("create temp object: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		// Best-effort close (no-op if already closed) and cleanup of the
		// temp file on every non-committed return path, including the
		// merkle-mismatch rejection.
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	tb := NewTreeBuilder()
	// MultiWriter tees each buffer to disk then to the incremental hasher;
	// CopyBuffer bounds the working set to streamCopyBufSize.
	buf := make([]byte, streamCopyBufSize)
	n, err := io.CopyBuffer(io.MultiWriter(tmp, tb), r, buf)
	if err != nil {
		return 0, fmt.Errorf("stream to disk: %w", err)
	}

	root, chunkHashes, err := tb.Finish()
	if err != nil {
		// Empty body, etc. — never a valid network object.
		return 0, fmt.Errorf("finalize merkle: %w", err)
	}
	if root != expectedRoot {
		return 0, ErrMerkleMismatch
	}

	// Durably flush bytes before the object becomes addressable.
	if err := tmp.Sync(); err != nil {
		return 0, fmt.Errorf("sync temp object: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close temp object: %w", err)
	}

	// Write the index FIRST, from the hashes computed during the single
	// pass. Ordering matters: if the rename below fails, an index with no
	// object is harmless cruft (not enumerated by List, GC-able), whereas an
	// object with no index would be challenged and fail, looking like lost
	// data. atomicWrite is itself temp+rename, so a partial index never
	// appears.
	idx := Index{
		ChunkSize:   DefaultChunkSize,
		TotalChunks: len(chunkHashes),
		ChunkHashes: chunkHashes,
	}
	idxBytes, err := json.Marshal(idx)
	if err != nil {
		return 0, fmt.Errorf("marshal index: %w", err)
	}
	if err := atomicWrite(s.idxPath(expectedRoot), idxBytes); err != nil {
		return 0, fmt.Errorf("write index: %w", err)
	}

	// Commit: atomic rename makes the verified bytes addressable. os.Rename
	// replaces an existing object (idempotent re-upload / re-replication).
	if err := os.Rename(tmpName, s.objPath(expectedRoot)); err != nil {
		return 0, fmt.Errorf("commit object: %w", err)
	}
	committed = true
	return n, nil
}

// SweepStaleObjectTemps removes ".tmp-stream-*" leftovers in the objects/
// directory whose mtime is older than maxAge. These are partial PutStream
// writes orphaned by a process kill mid-ingest (the normal error paths clean
// up their own temp inline). Mirrors SweepStaleStaging; safe to run from the
// same startup/periodic hook. Returns the count reclaimed and the first error
// encountered (continues past per-entry errors). A maxAge of a few hours is
// safe — it is longer than any legitimate in-flight upload.
//
// Note these orphans are already invisible to List/UsedBytes (non-hex names),
// so they never corrupt object enumeration or usage accounting — this sweep
// only reclaims their disk space.
func (s *Store) SweepStaleObjectTemps(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(s.objDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read objects dir: %w", err)
	}
	cutoff := time.Now().Add(-maxAge)
	cleaned := 0
	var firstErr error
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), objTempPrefix) {
			continue
		}
		path := filepath.Join(s.objDir, e.Name())
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cleaned++
	}
	return cleaned, firstErr
}
