package gc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeObject puts a merkle file in objects/ at the given path with
// some recognisable content. Used as the test fixture for round-trip
// rename and timer-reconstruction scenarios. It is local-helper-shaped
// rather than store-coupled because the quarantine package owns its
// filesystem layout regardless of what store.Store does next door.
func writeObject(t *testing.T, dataDir, merkle string, content []byte) {
	t.Helper()
	objDir := filepath.Join(dataDir, "objects")
	if err := os.MkdirAll(objDir, 0o755); err != nil {
		t.Fatalf("mkdir objects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(objDir, merkle), content, 0o644); err != nil {
		t.Fatalf("write object: %v", err)
	}
}

func TestQuarantine_NewCreatesDirs(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	if _, err := os.Stat(q.quarantineRoot()); err != nil {
		t.Errorf("quarantine root not created: %v", err)
	}
	if _, err := os.Stat(q.objectsRoot()); err != nil {
		t.Errorf("objects root not created: %v", err)
	}
}

func TestQuarantine_MoveAndRestore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	merkle := "abc123def"
	content := []byte("payload bytes")
	writeObject(t, dir, merkle, content)

	now := time.Now().UTC()
	if err := q.MoveToQuarantine(merkle, now); err != nil {
		t.Fatalf("MoveToQuarantine: %v", err)
	}
	if q.IsInObjects(merkle) {
		t.Errorf("file still in objects/ after move")
	}
	if !q.IsInQuarantine(merkle) {
		t.Errorf("file not in quarantine/ after move")
	}

	if err := q.RestoreFromQuarantine(merkle); err != nil {
		t.Fatalf("RestoreFromQuarantine: %v", err)
	}
	if !q.IsInObjects(merkle) {
		t.Errorf("file not in objects/ after restore")
	}
	if q.IsInQuarantine(merkle) {
		t.Errorf("file still in quarantine/ after restore")
	}

	// Bytes survive the round-trip identically.
	got, err := os.ReadFile(filepath.Join(q.objectsRoot(), merkle))
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content corrupted: got %q want %q", got, content)
	}
}

func TestQuarantine_MoveSetsMtimeToNow(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	merkle := "deadbeef"
	writeObject(t, dir, merkle, []byte("data"))

	// Pick a recognisable past timestamp to confirm the mtime really
	// got reset rather than picked up the original file mtime.
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(q.objectsRoot(), merkle), past, past); err != nil {
		t.Fatalf("chtimes original: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := q.MoveToQuarantine(merkle, now); err != nil {
		t.Fatalf("MoveToQuarantine: %v", err)
	}

	info, err := os.Stat(filepath.Join(q.quarantineRoot(), merkle))
	if err != nil {
		t.Fatalf("stat quarantine: %v", err)
	}
	got := info.ModTime().Truncate(time.Second)
	// Some filesystems clamp to second-resolution; allow a 2s window so
	// we don't flake on slow CI. Anything older than 2 days ago is
	// definitely the past timestamp leaking through.
	if got.Before(now.Add(-2 * time.Second)) {
		t.Errorf("mtime not advanced to now: got %v, expected near %v", got, now)
	}
}

func TestQuarantine_ListReconstructsTimersFromMtime(t *testing.T) {
	// Simulates the design §7 "provider restarts mid-quarantine"
	// case: GC has no sidecar bookkeeping, so on startup the timer
	// must be reconstructable from the on-disk mtime alone.
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}

	t1 := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	t2 := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	writeObject(t, dir, "aaa111", []byte("x"))
	writeObject(t, dir, "bbb222", []byte("yy"))
	if err := q.MoveToQuarantine("aaa111", t1); err != nil {
		t.Fatalf("move 1: %v", err)
	}
	if err := q.MoveToQuarantine("bbb222", t2); err != nil {
		t.Fatalf("move 2: %v", err)
	}

	// Simulate restart by constructing a fresh Quarantine against the
	// same data dir. No state file exists; everything must come from
	// the filesystem.
	q2, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine after restart: %v", err)
	}
	entries, err := q2.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after restart, got %d", len(entries))
	}
	// Sort guarantee from ListQuarantined: alphabetic by merkle.
	if entries[0].MerkleHex != "aaa111" || entries[1].MerkleHex != "bbb222" {
		t.Errorf("entries out of order: %+v", entries)
	}
	// Tolerate filesystem clamping; two-second margin is plenty.
	if entries[0].QuarantinedAt.Sub(t1).Abs() > 2*time.Second {
		t.Errorf("aaa111 mtime drift: got %v want %v", entries[0].QuarantinedAt, t1)
	}
	if entries[1].QuarantinedAt.Sub(t2).Abs() > 2*time.Second {
		t.Errorf("bbb222 mtime drift: got %v want %v", entries[1].QuarantinedAt, t2)
	}
	if entries[0].Bytes != 1 {
		t.Errorf("aaa111 size: got %d want 1", entries[0].Bytes)
	}
	if entries[1].Bytes != 2 {
		t.Errorf("bbb222 size: got %d want 2", entries[1].Bytes)
	}
}

func TestQuarantine_Unlink(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	merkle := "cafebabe"
	writeObject(t, dir, merkle, []byte("delete me"))
	if err := q.MoveToQuarantine(merkle, time.Now()); err != nil {
		t.Fatalf("move: %v", err)
	}

	if err := q.UnlinkFromQuarantine(merkle); err != nil {
		t.Fatalf("UnlinkFromQuarantine: %v", err)
	}
	if q.IsInQuarantine(merkle) {
		t.Errorf("file still in quarantine after unlink")
	}

	// Second unlink reports ErrNotInQuarantine — the destructive step
	// is louder than the merge-and-skip helpers because the caller
	// should know if a race happened.
	err = q.UnlinkFromQuarantine(merkle)
	if !errors.Is(err, ErrNotInQuarantine) {
		t.Errorf("expected ErrNotInQuarantine on double unlink, got %v", err)
	}
}

func TestQuarantine_MoveMissingObjectReturnsError(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	err = q.MoveToQuarantine("not_real", time.Now())
	if !errors.Is(err, ErrNotInObjects) {
		t.Errorf("expected ErrNotInObjects, got %v", err)
	}
}

func TestQuarantine_RestoreMissingReturnsError(t *testing.T) {
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	err = q.RestoreFromQuarantine("not_real")
	if !errors.Is(err, ErrNotInQuarantine) {
		t.Errorf("expected ErrNotInQuarantine, got %v", err)
	}
}

func TestQuarantine_OperatorMovesFileOutExternally(t *testing.T) {
	// Design §11 scenario 6: operator moves a file from
	// quarantine/<merkle>/ back to objects/<merkle>/ externally.
	// The sweeper must be able to detect this and treat the file as a
	// fresh marked_uncovered candidate with a timer based on mtime.
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	merkle := "f00ba4"
	writeObject(t, dir, merkle, []byte("payload"))
	if err := q.MoveToQuarantine(merkle, time.Now().UTC().Add(-1*time.Hour)); err != nil {
		t.Fatalf("move: %v", err)
	}

	// Simulate operator using `mv` outside the process.
	if err := os.Rename(
		filepath.Join(q.quarantineRoot(), merkle),
		filepath.Join(q.objectsRoot(), merkle),
	); err != nil {
		t.Fatalf("operator mv: %v", err)
	}
	// Touch the file with a recognisable "now" so the sweeper picks
	// up a fresh timer; the sweeper itself does this check by reading
	// the file's mtime.
	now := time.Now().UTC().Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(q.objectsRoot(), merkle), now, now); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if !q.IsInObjects(merkle) {
		t.Errorf("file not visible in objects/ after operator mv")
	}
	if q.IsInQuarantine(merkle) {
		t.Errorf("file still in quarantine/ after operator mv")
	}
	mt, err := q.ObjectMtime(merkle)
	if err != nil {
		t.Fatalf("ObjectMtime: %v", err)
	}
	if mt.Sub(now).Abs() > 2*time.Second {
		t.Errorf("ObjectMtime: got %v want near %v", mt, now)
	}
}

func TestQuarantine_ListIgnoresNonHexEntries(t *testing.T) {
	// Operators occasionally drop README.txt or .DS_Store files into
	// data dirs. ListQuarantined must ignore them so the sweeper
	// doesn't trip over operator-shaped detritus.
	dir := t.TempDir()
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	// Write a fake quarantined entry plus garbage files.
	writeObject(t, dir, "abcd", []byte("real"))
	if err := q.MoveToQuarantine("abcd", time.Now()); err != nil {
		t.Fatalf("move: %v", err)
	}
	if err := os.WriteFile(filepath.Join(q.quarantineRoot(), "README.txt"), []byte("ignore me"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if err := os.WriteFile(filepath.Join(q.quarantineRoot(), "not.hex"), []byte("ignore me too"), 0o644); err != nil {
		t.Fatalf("write garbage 2: %v", err)
	}

	entries, err := q.ListQuarantined()
	if err != nil {
		t.Fatalf("ListQuarantined: %v", err)
	}
	if len(entries) != 1 || entries[0].MerkleHex != "abcd" {
		t.Errorf("expected only abcd to surface, got %+v", entries)
	}
}
