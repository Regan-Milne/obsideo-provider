package store

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests for retention-authority Phase 1 coverage-cache state (D2).
// Transition semantics are the load-bearing piece; they govern when
// a grace period starts and whether an interim covered answer resets it.
//
// Spec: docs/retention_authority_design.md §6.2.

func TestUpdateCoverage_FirstWriteFromCoveredAnswer(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("a", 64)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ans := CoverageAnswer{Status: CoverageStatusCovered, Until: "2026-06-01T00:00:00Z"}

	if err := s.UpdateCoverage(merkle, ans, now); err != nil {
		t.Fatalf("UpdateCoverage: %v", err)
	}
	got, err := s.GetCoverage(merkle)
	if err != nil {
		t.Fatalf("GetCoverage: %v", err)
	}
	if got.Status != CoverageStatusCovered {
		t.Errorf("status = %q, want covered", got.Status)
	}
	if got.Until != "2026-06-01T00:00:00Z" {
		t.Errorf("until = %q, want 2026-06-01T00:00:00Z", got.Until)
	}
	if !got.RefreshedAt.Equal(now) {
		t.Errorf("refreshed_at = %v, want %v", got.RefreshedAt, now)
	}
	if got.FirstSeenUncovered != nil {
		t.Errorf("covered first-write: FirstSeenUncovered should be nil; got %v", got.FirstSeenUncovered)
	}
}

func TestUpdateCoverage_FirstWriteFromUncoveredAnswer_SetsTransitionMarker(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("b", 64)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ans := CoverageAnswer{Status: CoverageStatusUncovered, Reason: "contract_expired"}

	if err := s.UpdateCoverage(merkle, ans, now); err != nil {
		t.Fatalf("UpdateCoverage: %v", err)
	}
	got, _ := s.GetCoverage(merkle)
	if got.FirstSeenUncovered == nil {
		t.Fatal("FirstSeenUncovered should be set on first uncovered answer")
	}
	if !got.FirstSeenUncovered.Equal(now) {
		t.Errorf("FirstSeenUncovered = %v, want %v (the `now` of this refresh)", got.FirstSeenUncovered, now)
	}
	if got.Reason != "contract_expired" {
		t.Errorf("reason = %q, want contract_expired", got.Reason)
	}
}

func TestUpdateCoverage_FirstWriteFromOrphanedAnswer_SetsTransitionMarker(t *testing.T) {
	// Orphaned behaves like uncovered for grace-period tracking per §6.2.
	s := newTempStore(t)
	merkle := strings.Repeat("c", 64)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	ans := CoverageAnswer{Status: CoverageStatusOrphaned, Reason: "object_never_created"}

	if err := s.UpdateCoverage(merkle, ans, now); err != nil {
		t.Fatalf("UpdateCoverage: %v", err)
	}
	got, _ := s.GetCoverage(merkle)
	if got.FirstSeenUncovered == nil {
		t.Fatal("orphaned first-write: FirstSeenUncovered should be set")
	}
	if !got.FirstSeenUncovered.Equal(now) {
		t.Errorf("FirstSeenUncovered = %v, want %v", got.FirstSeenUncovered, now)
	}
}

func TestUpdateCoverage_StayingUncovered_PreservesOriginalTransitionTime(t *testing.T) {
	// The grace period is measured from FIRST_seen_uncovered. Subsequent
	// uncovered refreshes must not reset the clock.
	s := newTempStore(t)
	merkle := strings.Repeat("d", 64)
	t1 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	t3 := t1.Add(5 * 24 * time.Hour)

	if err := s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered, Reason: "contract_expired"}, t1); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered, Reason: "contract_expired"}, t2); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered, Reason: "contract_expired"}, t3); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetCoverage(merkle)
	if got.FirstSeenUncovered == nil || !got.FirstSeenUncovered.Equal(t1) {
		t.Errorf("FirstSeenUncovered = %v, want %v (original first-seen)", got.FirstSeenUncovered, t1)
	}
	if !got.RefreshedAt.Equal(t3) {
		t.Errorf("RefreshedAt = %v, want %v (most recent refresh)", got.RefreshedAt, t3)
	}
}

func TestUpdateCoverage_Covered_ClearsTransitionMarker(t *testing.T) {
	// If the root becomes uncovered, then later renewed to covered, the
	// grace-period clock MUST reset. A future uncovered answer should
	// start a new countdown.
	s := newTempStore(t)
	merkle := strings.Repeat("e", 64)
	t1 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(3 * 24 * time.Hour)

	// Start uncovered (sets marker at t1).
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered}, t1)

	// Become covered (clears marker).
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered, Until: "2026-07-01T00:00:00Z"}, t2)

	got, _ := s.GetCoverage(merkle)
	if got.FirstSeenUncovered != nil {
		t.Errorf("covered transition should clear FirstSeenUncovered; got %v", got.FirstSeenUncovered)
	}
}

func TestUpdateCoverage_FullCycle_CoveredUncoveredCoveredUncovered(t *testing.T) {
	// End-to-end: marker correctly tracks the MOST RECENT uncovered
	// transition, not the first one ever seen.
	s := newTempStore(t)
	merkle := strings.Repeat("f", 64)

	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(2 * 24 * time.Hour)
	t3 := t1.Add(3 * 24 * time.Hour)
	t4 := t1.Add(10 * 24 * time.Hour)

	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered}, t1) // marker = t1
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered, Until: "2026-06-01T00:00:00Z"}, t2) // marker cleared
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered, Until: "2026-06-01T00:00:00Z"}, t3) // still covered, still no marker
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered, Reason: "contract_expired"}, t4) // marker = t4

	got, _ := s.GetCoverage(merkle)
	if got.FirstSeenUncovered == nil || !got.FirstSeenUncovered.Equal(t4) {
		t.Errorf("FirstSeenUncovered = %v, want %v (most recent transition)", got.FirstSeenUncovered, t4)
	}
}

func TestUpdateCoverage_UncoveredToOrphaned_PreservesTransitionTime(t *testing.T) {
	// Both uncovered and orphaned should be treated as "non-covered" for
	// grace-period purposes; transitioning between them must not reset
	// the timer. The spec says both trigger prune-eligibility after the
	// same grace period elapses.
	s := newTempStore(t)
	merkle := strings.Repeat("9", 64)
	t1 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)

	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusUncovered}, t1)
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusOrphaned}, t2)

	got, _ := s.GetCoverage(merkle)
	if got.FirstSeenUncovered == nil || !got.FirstSeenUncovered.Equal(t1) {
		t.Errorf("FirstSeenUncovered = %v, want %v (preserved across uncovered→orphaned)", got.FirstSeenUncovered, t1)
	}
	if got.Status != CoverageStatusOrphaned {
		t.Errorf("status = %q, want orphaned", got.Status)
	}
}

func TestGetCoverage_ReturnsErrNotFoundWhenAbsent(t *testing.T) {
	s := newTempStore(t)
	_, err := s.GetCoverage("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestHasCoverage_TrueAfterWrite(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("7", 64)
	if s.HasCoverage(merkle) {
		t.Fatal("HasCoverage true before write")
	}
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered}, time.Now())
	if !s.HasCoverage(merkle) {
		t.Error("HasCoverage false after write")
	}
}

func TestDeleteCoverage_RemovesFile(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("8", 64)
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered}, time.Now())
	if err := s.DeleteCoverage(merkle); err != nil {
		t.Fatal(err)
	}
	if s.HasCoverage(merkle) {
		t.Error("coverage file persists after DeleteCoverage")
	}
	// DeleteCoverage on non-existent file must be a no-op, not an error.
	if err := s.DeleteCoverage(merkle); err != nil {
		t.Errorf("DeleteCoverage on absent file: want nil, got %v", err)
	}
}

func TestDelete_RemovesCoverageFile(t *testing.T) {
	// Object delete also sweeps the coverage file so stale state does not
	// linger on disk.
	s := newTempStore(t)
	merkle := strings.Repeat("6", 64)
	_ = s.Put(merkle, []byte("x"), DefaultChunkSize)
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered}, time.Now())

	if err := s.Delete(merkle); err != nil {
		t.Fatal(err)
	}
	if s.HasCoverage(merkle) {
		t.Error("coverage file persists after Delete")
	}
}

func TestCoverage_FileIsMutable_NotMode0o444(t *testing.T) {
	// Unlike ownership files (immutable 0o444), coverage files must be
	// writable so refreshes overwrite. Skip on Windows where mode bits
	// are cosmetic.
	if runtime.GOOS == "windows" {
		t.Skip("file mode semantics differ on Windows")
	}
	s := newTempStore(t)
	merkle := strings.Repeat("5", 64)
	_ = s.UpdateCoverage(merkle, CoverageAnswer{Status: CoverageStatusCovered}, time.Now())
	info, err := os.Stat(s.covPath(merkle))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o200 == 0 {
		t.Errorf("coverage file must be writable (owner has +w); got mode %o", info.Mode()&0o777)
	}
}

func TestCoverage_JSONFieldNamesMatchSpec(t *testing.T) {
	// Spec §9 schema: status, until, reason, refreshed_at, first_seen_uncovered.
	s := newTempStore(t)
	merkle := strings.Repeat("4", 64)
	_ = s.UpdateCoverage(merkle,
		CoverageAnswer{Status: CoverageStatusUncovered, Reason: "contract_expired"},
		time.Now())
	raw, err := os.ReadFile(s.covPath(merkle))
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	for _, key := range []string{
		`"status"`,
		`"reason"`,
		`"refreshed_at"`,
		`"first_seen_uncovered"`,
	} {
		if !strings.Contains(content, key) {
			t.Errorf("coverage file missing JSON field %s; got: %s", key, content)
		}
	}
}
