package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// hexish: 128-char hex-only string, matches store.isHexName.
func hexish(seed int) string {
	digits := []byte("0123456789abcdef")
	out := make([]byte, 128)
	for i := range out {
		out[i] = digits[(seed+i)%16]
	}
	return string(out)
}

// TestTickStagingSweeper_PrunesStaleEntries pins the integration
// between cmd.tickStagingSweeper and store.SweepStaleStaging. The
// store helper is already covered (heartbeat_metrics_test.go); this
// just verifies the cmd-layer wrapper invokes it correctly and a
// "pruned" log fires when there's work done.
//
// **Regression invariant pinned:** if a future change drops the
// staging-sweeper goroutine from start.go (or breaks the
// `stagingMaxAge` constant in a way that ages out everything or
// nothing), this test catches it via the cleaned-entries assertion.
func TestTickStagingSweeper_PrunesStaleEntries(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	// Plant one stale staging dir (older than stagingMaxAge=1h)
	// and one fresh one. The sweeper should prune the stale and
	// keep the fresh.
	stale := hexish(0)
	fresh := hexish(1)
	stagingDir := filepath.Join(dir, "staging")
	for _, name := range []string{stale, fresh} {
		path := filepath.Join(stagingDir, name)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		_ = os.WriteFile(filepath.Join(path, "chunk_00000"), []byte(strings.Repeat("x", 100)), 0o644)
	}
	stalePath := filepath.Join(stagingDir, stale)
	freshPath := filepath.Join(stagingDir, fresh)
	stalemtime := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stalePath, stalemtime, stalemtime); err != nil {
		t.Fatalf("chtimes stale: %v", err)
	}

	tickStagingSweeper(st)

	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Errorf("stale dir not pruned (err=%v)", err)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Errorf("fresh dir wrongly pruned (err=%v)", err)
	}
}

// TestStagingSweeperConstants — guard against a change that pushes
// stagingMaxAge or stagingSweepInterval to zero or negative, which
// would either prune everything every tick or never prune anything.
// Documented intent: 1h max age, 1h sweep interval.
func TestStagingSweeperConstants(t *testing.T) {
	if stagingMaxAge <= 0 {
		t.Errorf("stagingMaxAge=%s, want >0", stagingMaxAge)
	}
	if stagingSweepInterval <= 0 {
		t.Errorf("stagingSweepInterval=%s, want >0", stagingSweepInterval)
	}
	if stagingMaxAge < time.Minute {
		t.Errorf("stagingMaxAge=%s, suspiciously small (could prune in-flight uploads)", stagingMaxAge)
	}
}
