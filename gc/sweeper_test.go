package gc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/store"
)

// fakeRechecker is the test seam injected via SweeperOpts.Rechecker.
// Per-merkle answer maps avoid the trap of "every recheck returns the
// same value" — most §11 scenarios depend on a single merkle behaving
// differently from another, or on the recheck answer changing across
// cycles.
type fakeRechecker struct {
	mu      sync.Mutex
	answers map[string]rechAns
}

type rechAns struct {
	contracted bool
	reason     string
	err        error
}

func newFakeRechecker() *fakeRechecker {
	return &fakeRechecker{answers: map[string]rechAns{}}
}

// set writes an explicit contracted answer. true = contracted (paying);
// false = non-contracted (GC candidate).
func (f *fakeRechecker) set(merkle string, contracted bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[merkle] = rechAns{contracted: contracted}
}

func (f *fakeRechecker) setError(merkle, reason string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[merkle] = rechAns{reason: reason, err: err}
}

func (f *fakeRechecker) Recheck(_ context.Context, merkle string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.answers[merkle]
	if !ok {
		// Unset means "coord says contracted." This default is the
		// safety bias: a test that forgot to wire an answer never
		// accidentally triggers a delete.
		return true, "", nil
	}
	return a.contracted, a.reason, a.err
}

// fakeStorage is an in-memory replacement for the *store.Store calls
// the sweeper makes for terminal cleanup. Tracks which merkles got
// their index/ownership removed and which got their coverage cache
// removed so the test can assert the cleanup happened.
type fakeStorage struct {
	mu                     sync.Mutex
	deletedIndexOwnership  map[string]bool
	deletedCoverage        map[string]bool
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{
		deletedIndexOwnership: map[string]bool{},
		deletedCoverage:       map[string]bool{},
	}
}

func (f *fakeStorage) DeleteIndexAndOwnership(merkleHex string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedIndexOwnership[merkleHex] = true
	return nil
}

func (f *fakeStorage) DeleteCoverage(merkleHex string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deletedCoverage[merkleHex] = true
	return nil
}

// fixture is the per-test data dir + plumbed components. Constructing
// the real *store.Store gets us free coverage-cache integration so the
// sweeper exercises the same UpdateCoverage transition rules production
// will hit.
type fixture struct {
	t          *testing.T
	dataDir    string
	store      *store.Store
	quarantine *Quarantine
	rechecker  *fakeRechecker
	storage    *fakeStorage
	now        time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	q, err := NewQuarantine(dir)
	if err != nil {
		t.Fatalf("NewQuarantine: %v", err)
	}
	return &fixture{
		t:          t,
		dataDir:    dir,
		store:      st,
		quarantine: q,
		rechecker:  newFakeRechecker(),
		storage:    newFakeStorage(),
		now:        time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
	}
}

func (f *fixture) sweeper(cfg Config) *Sweeper {
	cfg.Enabled = true
	if cfg.RetentionNonContractedHours == 0 {
		cfg.RetentionNonContractedHours = 48
	}
	if cfg.QuarantineHours == 0 {
		cfg.QuarantineHours = 6
	}
	if cfg.SweepIntervalHours == 0 {
		cfg.SweepIntervalHours = 6
	}
	s, err := NewSweeper(SweeperOpts{
		Config:     cfg,
		Coverage:   f.store,
		Quarantine: f.quarantine,
		Rechecker:  f.rechecker,
		Storage:    f.storage,
		Now:        func() time.Time { return f.now },
	})
	if err != nil {
		f.t.Fatalf("NewSweeper: %v", err)
	}
	return s
}

// putNonContracted seeds an object on disk + coverage cache marking it
// uncovered as of `firstSeen`. The bytes are non-empty so file size
// metrics aren't accidentally zero-tolerant.
//
// The file's mtime is forced to firstSeen so the sweeper's
// operator-restoration heuristic (mt.After(firstSeen)) does not
// spuriously fire in tests — store.Put writes the file at real wall
// time, but our fixture's "now" is a fake offset, so without this
// pin the mtime would always look "newer" than firstSeen and reset
// the timer.
func (f *fixture) putNonContracted(merkle string, firstSeen time.Time) {
	f.t.Helper()
	if err := f.store.Put(merkle, []byte("payload"), 1024); err != nil {
		f.t.Fatalf("store.Put: %v", err)
	}
	if err := f.store.UpdateCoverage(merkle, store.CoverageAnswer{
		Status:     store.CoverageStatusUncovered,
		Contracted: false,
		Reason:     "contract_expired",
	}, firstSeen); err != nil {
		f.t.Fatalf("UpdateCoverage: %v", err)
	}
	objPath := filepath.Join(f.quarantine.objectsRoot(), merkle)
	if err := os.Chtimes(objPath, firstSeen, firstSeen); err != nil {
		f.t.Fatalf("chtimes object: %v", err)
	}
}

// putContracted seeds an object as contracted (paying). Used for the
// negative test (paid-active-unexpired data, must never be touched).
func (f *fixture) putContracted(merkle string) {
	f.t.Helper()
	if err := f.store.Put(merkle, []byte("paid bytes"), 1024); err != nil {
		f.t.Fatalf("store.Put: %v", err)
	}
	if err := f.store.UpdateCoverage(merkle, store.CoverageAnswer{
		Status:     store.CoverageStatusCovered,
		Contracted: true,
		Until:      "2099-01-01T00:00:00Z",
	}, f.now); err != nil {
		f.t.Fatalf("UpdateCoverage: %v", err)
	}
}

// advance moves the fixture's "now" forward. The sweeper reads time
// through the injected Now closure so this is the only mechanism a
// test needs to age out a window.
func (f *fixture) advance(d time.Duration) {
	f.now = f.now.Add(d)
}

// runOnce is a thin wrapper to keep the test bodies readable.
func (f *fixture) runOnce(s *Sweeper) {
	f.t.Helper()
	if err := s.RunOnce(context.Background()); err != nil {
		f.t.Fatalf("RunOnce: %v", err)
	}
}

// ─── Scenario 1: Happy path ─────────────────────────────────────────────────

func TestScenario1_HappyPath(t *testing.T) {
	// Uncontracted object → full state machine → deleted + cleanup.
	f := newFixture(t)
	merkle := "aa"
	f.putNonContracted(merkle, f.now)
	f.rechecker.set(merkle, false)

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	// Cycle 1: inside retention window, file stays in objects/.
	f.runOnce(s)
	if !f.quarantine.IsInObjects(merkle) {
		t.Fatalf("cycle 1: file should still be in objects/")
	}
	if f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("cycle 1: file should not be in quarantine yet")
	}

	// Advance past retention. Now eligible.
	f.advance(49 * time.Hour)
	f.runOnce(s)
	if f.quarantine.IsInObjects(merkle) {
		t.Fatalf("cycle 2: file should have moved to quarantine")
	}
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("cycle 2: file should be in quarantine")
	}
	if got := s.Metrics().Quarantined.Load(); got != 1 {
		t.Errorf("Quarantined counter: got %d want 1", got)
	}

	// Inside quarantine window, no unlink yet.
	f.advance(1 * time.Hour)
	f.runOnce(s)
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("cycle 3: file should still be in quarantine")
	}

	// Past quarantine window + recheck still uncovered → unlink.
	f.advance(7 * time.Hour)
	f.runOnce(s)
	if f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("cycle 4: file should have been unlinked")
	}
	if got := s.Metrics().Unlinked.Load(); got != 1 {
		t.Errorf("Unlinked counter: got %d want 1", got)
	}
	if !f.storage.deletedIndexOwnership[merkle] {
		t.Errorf("index/ownership not cleaned up")
	}
	if !f.storage.deletedCoverage[merkle] {
		t.Errorf("coverage record not cleaned up")
	}
}

// ─── Scenario 2: Negative test (load-bearing) ───────────────────────────────

func TestScenario2_PaidObjectNeverTouched(t *testing.T) {
	// Paid + active + unexpired customer object. Sweep runs across
	// the full retention window. Object is never touched.
	f := newFixture(t)
	merkle := "bb"
	f.putContracted(merkle)
	// rechecker default-answer is "covered" so the recheck path is
	// already biased away from deletion. Set it explicitly anyway.
	f.rechecker.set(merkle, true)

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	// Run sweeps across multiple times the retention window. Object
	// must remain in objects/ across every cycle. Hardware and
	// algorithmic determinism: the loop runs the file through the
	// candidate set every time and the sweeper has every chance to
	// misbehave; it must not.
	for i := 0; i < 12; i++ {
		f.runOnce(s)
		if !f.quarantine.IsInObjects(merkle) {
			t.Fatalf("paid object touched at cycle %d", i)
		}
		if f.quarantine.IsInQuarantine(merkle) {
			t.Fatalf("paid object quarantined at cycle %d", i)
		}
		f.advance(10 * time.Hour)
	}
	if got := s.Metrics().Quarantined.Load(); got != 0 {
		t.Errorf("Quarantined counter: got %d want 0", got)
	}
	if got := s.Metrics().Unlinked.Load(); got != 0 {
		t.Errorf("Unlinked counter: got %d want 0", got)
	}
}

// ─── Scenario 3: Mid-window pay ─────────────────────────────────────────────

func TestScenario3_MidWindowPay(t *testing.T) {
	// Account flips to paid while file is in quarantined state.
	// Sweeper must restore the file and clear first_seen_uncovered.
	f := newFixture(t)
	merkle := "cc"
	f.putNonContracted(merkle, f.now)
	f.rechecker.set(merkle, false)

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	// Get the file into quarantine.
	f.advance(49 * time.Hour)
	f.runOnce(s)
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("expected file in quarantine after eligible-cycle")
	}

	// Customer pays. Live recheck now says covered.
	f.rechecker.set(merkle, true)
	f.advance(1 * time.Hour) // still inside quarantine window
	f.runOnce(s)

	if !f.quarantine.IsInObjects(merkle) {
		t.Fatalf("file not restored to objects/ after coverage flip")
	}
	if f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("file still in quarantine after coverage flip")
	}
	if got := s.Metrics().Recovered.Load(); got != 1 {
		t.Errorf("Recovered counter: got %d want 1", got)
	}

	// Subsequent challenge / read still works (file is back, intact).
	got, err := f.store.Get(merkle)
	if err != nil {
		t.Fatalf("store.Get after restore: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("restored content corrupted: %q", got)
	}
}

// ─── Scenario 4: Coord-blip during recheck ──────────────────────────────────

func TestScenario4_CoordBlipDuringRecheck(t *testing.T) {
	// Recheck returns 5xx / timeout / unreachable at the moment the
	// sweeper would unlink. Object stays put, recheck-failure counter
	// increments, next sweep retries cleanly.
	f := newFixture(t)
	merkle := "dd"
	f.putNonContracted(merkle, f.now)
	f.rechecker.setError(merkle, "5xx", errors.New("coord 503: backend down"))

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	// Advance past retention; recheck fails.
	f.advance(49 * time.Hour)
	f.runOnce(s)

	// File MUST remain in objects/ — coord blip means no delete.
	if !f.quarantine.IsInObjects(merkle) {
		t.Fatalf("file moved despite coord blip")
	}
	if f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("file quarantined despite coord blip")
	}
	if got := s.Metrics().Recheck5xx.Load(); got != 1 {
		t.Errorf("Recheck5xx counter: got %d want 1", got)
	}

	// Coord recovers. Next sweep proceeds normally.
	f.rechecker.set(merkle, false)
	f.runOnce(s)
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("file not quarantined after recovery")
	}

	// Variant: timeout during quarantine-unlink recheck stops the
	// terminal step too.
	f.rechecker.setError(merkle, "timeout", context.DeadlineExceeded)
	f.advance(7 * time.Hour) // past quarantine window
	f.runOnce(s)
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("file unlinked despite timeout on terminal recheck")
	}
	if got := s.Metrics().RecheckTimeout.Load(); got < 1 {
		t.Errorf("RecheckTimeout counter: got %d want >=1", got)
	}
}

// ─── Scenario 5: Stale-cache safety ─────────────────────────────────────────

func TestScenario5_StaleCacheSafety(t *testing.T) {
	// Coverage cache says uncovered, fresh coord query says contracted.
	// Recheck-before-delete catches the discrepancy; file stays.
	f := newFixture(t)
	merkle := "ee"
	f.putNonContracted(merkle, f.now)
	// The CACHE says uncovered (set by putNonContracted above). The
	// LIVE recheck says covered. This is the discrepancy the recheck
	// path must catch.
	f.rechecker.set(merkle, true)

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	f.advance(49 * time.Hour)
	f.runOnce(s)

	if !f.quarantine.IsInObjects(merkle) {
		t.Fatalf("stale-cache delete fired: file moved out of objects/")
	}
	if f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("stale-cache delete fired: file in quarantine")
	}
	if got := s.Metrics().Quarantined.Load(); got != 0 {
		t.Errorf("Quarantined counter incremented despite stale cache: %d", got)
	}
}

// ─── Scenario 6: Manual operator intervention ──────────────────────────────

func TestScenario6_ManualOperatorIntervention(t *testing.T) {
	// Operator moves a file from quarantine/<merkle>/ back to
	// objects/<merkle>/ externally. Next sweep treats it as
	// marked_uncovered again with timer based on file mtime.
	f := newFixture(t)
	merkle := "ff"
	f.putNonContracted(merkle, f.now)
	f.rechecker.set(merkle, false)

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	// Cycle the file into quarantine.
	f.advance(49 * time.Hour)
	f.runOnce(s)
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("expected quarantine")
	}

	// Operator does an external `mv` back to objects/. Set a fresh
	// mtime so the sweeper's mtime-based timer reset is meaningful.
	mvNow := f.now.Add(30 * time.Minute) // some time after move-to-quarantine
	if err := os.Rename(
		filepath.Join(f.quarantine.quarantineRoot(), merkle),
		filepath.Join(f.quarantine.objectsRoot(), merkle),
	); err != nil {
		t.Fatalf("operator mv: %v", err)
	}
	if err := os.Chtimes(filepath.Join(f.quarantine.objectsRoot(), merkle), mvNow, mvNow); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Advance only a few hours — well inside the retention window
	// from the mv mtime. Sweeper must not re-quarantine.
	f.advance(2 * time.Hour)
	f.runOnce(s)
	if !f.quarantine.IsInObjects(merkle) {
		t.Fatalf("file re-quarantined too soon after operator intervention")
	}

	// Now advance past the full retention window from mv time. Sweeper
	// should re-quarantine because the timer is based on mv mtime,
	// not the original first_seen_uncovered.
	f.advance(50 * time.Hour)
	f.runOnce(s)
	if !f.quarantine.IsInQuarantine(merkle) {
		t.Fatalf("file should have been re-quarantined after fresh window elapsed")
	}
}

// ─── Cross-cutting: gauge values ────────────────────────────────────────────

func TestSweeper_GaugesReflectState(t *testing.T) {
	// Quick sanity that the gauges (point-in-time counts) match what
	// is on disk after a sweep. The counter tests above cover the
	// monotonic counters; this is the missing observability piece.
	f := newFixture(t)
	f.putNonContracted("a1", f.now)
	f.putNonContracted("a2", f.now)
	f.putContracted("a3")
	f.rechecker.set("a1", false)
	f.rechecker.set("a2", false)

	s := f.sweeper(Config{
		RetentionNonContractedHours: 48,
		QuarantineHours:         6,
		SweepIntervalHours:      6,
	})

	// Inside retention: both a1, a2 are marked_uncovered; a3 is covered.
	f.runOnce(s)
	if got := s.Metrics().GaugeMarkedUncontracted.Load(); got != 2 {
		t.Errorf("GaugeMarkedUncontracted: got %d want 2", got)
	}
	if got := s.Metrics().GaugeQuarantined.Load(); got != 0 {
		t.Errorf("GaugeQuarantined: got %d want 0", got)
	}

	// Past retention: both should quarantine.
	f.advance(49 * time.Hour)
	f.runOnce(s)
	if got := s.Metrics().GaugeQuarantined.Load(); got != 2 {
		t.Errorf("GaugeQuarantined: got %d want 2", got)
	}
}

// ─── Cross-cutting: NewSweeper validation ───────────────────────────────────

func TestNewSweeper_RequiresAllSeams(t *testing.T) {
	// The constructor must reject a nil Rechecker because that would
	// silently bypass the recheck-before-delete guarantee.
	_, err := NewSweeper(SweeperOpts{
		Config:     Config{Enabled: true},
		Coverage:   newFakeCovReader(),
		Quarantine: &Quarantine{},
		Rechecker:  nil, // <-- the dangerous one
		Storage:    newFakeStorage(),
	})
	if err == nil {
		t.Fatalf("NewSweeper should reject nil Rechecker")
	}
}

// fakeCovReader is a minimal CoverageReader stub for the constructor
// validation test. We don't need it to do anything useful.
type fakeCovReader struct{}

func newFakeCovReader() *fakeCovReader                            { return &fakeCovReader{} }
func (*fakeCovReader) List() ([]string, error)                    { return nil, nil }
func (*fakeCovReader) GetCoverage(string) (*store.Coverage, error) { return nil, store.ErrNotFound }
func (*fakeCovReader) UpdateCoverage(string, store.CoverageAnswer, time.Time) error {
	return nil
}
