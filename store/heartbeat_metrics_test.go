package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the heartbeat-feeding store helpers added 2026-05-02:
// UsedBytes, DiskFreeBytes, and SweepStaleStaging. These close the
// "no test for cmd/heartbeat.go" GAP from the storage_provider
// functional contract — by covering the store-layer primitives the
// heartbeat depends on, the heartbeat refactor in
// cmd/heartbeat_test.go can use small focused unit tests rather than
// big end-to-end ones.

// hexMerkle returns a deterministic 128-char hex-looking name. The
// store helpers gate on isHexName(), so tests must use hex-looking
// names or the file is silently skipped.
func hexMerkle(n int) string {
	digits := []byte("0123456789abcdef")
	out := make([]byte, 128)
	for i := range out {
		out[i] = digits[(n+i)%16]
	}
	return string(out)
}

// TestUsedBytes_SumsObjectsCorrectly is the regression test for the
// pre-2026-05-02 heartbeat bug where used_bytes was hardcoded to 0
// in cmd/heartbeat.go:80. With UsedBytes() returning the ground-truth
// sum, the heartbeat can finally report what's actually on disk —
// closing the "coord ledger says 444 MiB, provider self-reports
// 1.15 MiB" discrepancy Reg surfaced from the operator console.
func TestUsedBytes_SumsObjectsCorrectly(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	// Empty store: zero.
	got, err := s.UsedBytes()
	if err != nil {
		t.Fatalf("UsedBytes empty: %v", err)
	}
	if got != 0 {
		t.Fatalf("empty store UsedBytes = %d, want 0", got)
	}

	// Plant three hex-named files of known sizes.
	sizes := []int{100, 2048, 1048576}
	wantTotal := int64(0)
	for i, sz := range sizes {
		name := hexMerkle(i)
		body := make([]byte, sz)
		if err := os.WriteFile(filepath.Join(s.objDir, name), body, 0o644); err != nil {
			t.Fatalf("plant %d: %v", i, err)
		}
		wantTotal += int64(sz)
	}

	got, err = s.UsedBytes()
	if err != nil {
		t.Fatalf("UsedBytes after plant: %v", err)
	}
	if got != wantTotal {
		t.Fatalf("UsedBytes = %d, want %d", got, wantTotal)
	}
}

// TestUsedBytes_SkipsNonHexNames pins the parity with List(): only
// real merkle-named files count toward used_bytes. Atomic-write temp
// files (.tmp-*) and any junk in the dir are skipped, otherwise the
// reported total drifts up during a write and back down after rename.
func TestUsedBytes_SkipsNonHexNames(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)

	// One real object, one tmp-file, one random junk.
	_ = os.WriteFile(filepath.Join(s.objDir, hexMerkle(0)), make([]byte, 1000), 0o644)
	_ = os.WriteFile(filepath.Join(s.objDir, ".tmp-12345"), make([]byte, 9999), 0o644)
	_ = os.WriteFile(filepath.Join(s.objDir, "junk.txt"), make([]byte, 5555), 0o644)

	got, err := s.UsedBytes()
	if err != nil {
		t.Fatalf("UsedBytes: %v", err)
	}
	if got != 1000 {
		t.Fatalf("UsedBytes = %d, want 1000 (only the hex-named file should count)", got)
	}
}

// TestDiskFreeBytes_NonZeroOnRealFilesystem is a cross-platform
// smoke test. Asserting an exact number is impossible (the test
// runs on whatever filesystem t.TempDir picks), but a real volume
// in a real test run always has > 0 bytes free — the value being
// non-zero proves the syscall plumbing works end-to-end on the
// platform the test runs on. CI on linux + dev on windows both
// hit this.
func TestDiskFreeBytes_NonZeroOnRealFilesystem(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	got, err := s.DiskFreeBytes()
	if err != nil {
		t.Fatalf("DiskFreeBytes: %v", err)
	}
	if got <= 0 {
		t.Fatalf("DiskFreeBytes = %d, want > 0", got)
	}
}

// TestSweepStaleStaging_PrunesOldKeepsNew exercises the orphan-
// staging-cruft fix that closes the Yala-class "declared X capacity
// but full at Y < X" loop. Failed uploads leave staging dirs behind;
// the sweeper prunes anything older than maxAge.
func TestSweepStaleStaging_PrunesOldKeepsNew(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)

	now := time.Now()
	// Three staging dirs with mtimes spanning the cutoff.
	cases := []struct {
		merkle    string
		mtimeAge  time.Duration
		shouldGo  bool
	}{
		{hexMerkle(0), 2 * time.Hour, true},  // very old → prune
		{hexMerkle(1), 65 * time.Minute, true}, // just over cutoff → prune
		{hexMerkle(2), 30 * time.Minute, false}, // fresh → keep
	}
	for _, c := range cases {
		dPath := s.StagingDirPath(c.merkle)
		if err := os.MkdirAll(dPath, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", c.merkle, err)
		}
		_ = os.WriteFile(filepath.Join(dPath, "chunk_00000"), []byte("x"), 0o644)
		// Backdate the dir's mtime so the sweeper sees the simulated age.
		if err := os.Chtimes(dPath, now.Add(-c.mtimeAge), now.Add(-c.mtimeAge)); err != nil {
			t.Fatalf("chtimes %s: %v", c.merkle, err)
		}
	}

	// Plant a non-hex dir to verify it's left alone (defensive).
	otherDir := filepath.Join(s.stagingDir, ".tmpwork")
	_ = os.MkdirAll(otherDir, 0o755)
	_ = os.Chtimes(otherDir, now.Add(-3*time.Hour), now.Add(-3*time.Hour))

	cleaned, err := s.SweepStaleStaging(time.Hour)
	if err != nil {
		t.Fatalf("SweepStaleStaging: %v", err)
	}
	if cleaned != 2 {
		t.Errorf("cleaned=%d, want 2 (the two old hex-named dirs)", cleaned)
	}

	// Verify the keep-fresh dir survived.
	if _, err := os.Stat(s.StagingDirPath(cases[2].merkle)); err != nil {
		t.Errorf("fresh dir was wrongly pruned: %v", err)
	}
	// Verify the two old dirs are gone.
	for i := 0; i < 2; i++ {
		if _, err := os.Stat(s.StagingDirPath(cases[i].merkle)); !os.IsNotExist(err) {
			t.Errorf("old dir %s should be removed; stat err=%v", cases[i].merkle, err)
		}
	}
	// Non-hex dir should be untouched.
	if _, err := os.Stat(otherDir); err != nil {
		t.Errorf("non-hex dir was wrongly pruned: %v", err)
	}
}

// TestSweepStaleStaging_MissingStagingDirIsNotAnError. If the staging
// dir was never created (fresh install, or admin manually wiped),
// the sweeper should return (0, nil) — the dir not existing is not
// an error condition for "is there anything to clean."
func TestSweepStaleStaging_MissingStagingDirIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	// Remove the staging dir New() creates.
	if err := os.RemoveAll(s.stagingDir); err != nil {
		t.Fatalf("rm staging: %v", err)
	}
	cleaned, err := s.SweepStaleStaging(time.Hour)
	if err != nil {
		t.Errorf("missing staging dir: err=%v, want nil", err)
	}
	if cleaned != 0 {
		t.Errorf("missing staging dir: cleaned=%d, want 0", cleaned)
	}
}

// TestSweepStaleStaging_EmptyStagingDirReturnsZero. Sane "nothing
// to do" path: staging dir exists but empty.
func TestSweepStaleStaging_EmptyStagingDirReturnsZero(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)
	cleaned, err := s.SweepStaleStaging(time.Hour)
	if err != nil {
		t.Fatalf("empty staging: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("empty staging: cleaned=%d, want 0", cleaned)
	}
}

// Ensure the helper isn't accidentally aggressive — a staging dir
// inside a deeper structure (chunked files within) still gets nuked
// as a unit when stale.
func TestSweepStaleStaging_RemovesNestedContents(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir)

	merkle := hexMerkle(7)
	dPath := s.StagingDirPath(merkle)
	if err := os.MkdirAll(dPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for i := 0; i < 5; i++ {
		_ = os.WriteFile(filepath.Join(dPath, "chunk_0000"+string(rune('0'+i))), []byte(strings.Repeat("x", 1024)), 0o644)
	}
	_ = os.WriteFile(filepath.Join(dPath, "meta"), []byte("5"), 0o644)
	_ = os.Chtimes(dPath, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour))

	cleaned, err := s.SweepStaleStaging(time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("cleaned=%d, want 1", cleaned)
	}
	if _, err := os.Stat(dPath); !os.IsNotExist(err) {
		t.Errorf("dir survived: %v", err)
	}
}
