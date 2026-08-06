package gc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/coverage"
)

// ---------------------------------------------------------------------
// Predicate tests: does GC ask the RIGHT question?
//
// The pre-existing sweeper tests inject a fakeRechecker and set the
// boolean directly, so they prove the timer/quarantine state machine is
// correct GIVEN a correct answer. They cannot catch a wrong answer —
// which is why 24 green tests coexisted with the 2026-07-31 incident,
// where GC unlinked 1,421 live verified objects belonging to an ACTIVE
// ENTERPRISE customer because it read the coordinator's paid-only
// billing field.
//
// These tests sit at the seam BELOW the fake: the real clientRechecker
// against a real coordinator JSON response.
// ---------------------------------------------------------------------

const testMerkle = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// coordServing stands up a fake coordinator returning one raw JSON body
// for the roots-status query, and returns a rechecker wired to it.
func coordServing(t *testing.T, body string) (CoverageRechecker, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return CoverageRecheckerFromClient(DefaultClient(srv.URL, "test-key", srv.Client())), srv.Close
}

// TestRecheck_TheIncident is the regression guard for 2026-07-31, in the
// exact shape the coordinator reports for an active enterprise account:
// covered and retained, but NOT contracted (enterprise generates no
// per-TB revenue, so the billing predicate is false).
//
// Reading `contracted` here returns false -> "reclaim it" -> data loss.
// Reading `retained` returns true -> "keep it" -> correct.
func TestRecheck_TheIncident_EnterpriseIsRetainedButNotContracted(t *testing.T) {
	r, done := coordServing(t, `{"`+testMerkle+`":{"status":"covered","reclaimable":false,"contracted":false}}`)
	defer done()

	notReclaimable, reason, err := r.Recheck(context.Background(), testMerkle)
	if err != nil {
		t.Fatalf("unexpected error: %v (reason=%s)", err, reason)
	}
	if !notReclaimable {
		t.Fatal("active enterprise account reported as NOT retained — this is the " +
			"2026-07-31 incident: GC would unlink live customer data")
	}
}

// TestRecheck_RefusesWhenCoordOmitsReclaimable: a coordinator too old to
// answer the retention question must not be fallen back on, because its
// only answer is the billing one that caused the incident. No usable
// answer means no deletion.
func TestRecheck_RefusesWhenCoordOmitsReclaimable(t *testing.T) {
	// Old coord: `contracted` only, and it says false (would delete).
	r, done := coordServing(t, `{"`+testMerkle+`":{"status":"covered","contracted":false}}`)
	defer done()

	_, reason, err := r.Recheck(context.Background(), testMerkle)
	if err == nil {
		t.Fatal("expected an unusable-answer error when coord omits `reclaimable`")
	}
	if !errors.Is(err, ErrRecheckUnusable) {
		t.Fatalf("error must wrap ErrRecheckUnusable so the sweeper skips; got %v", err)
	}
	if reason != "no_reclaimable_field" {
		t.Errorf("reason = %q, want %q", reason, "no_reclaimable_field")
	}
}

// A genuinely non-retained account (expired paid) must still be
// reclaimable — the fix must not make GC a no-op.
func TestRecheck_ExpiredPaidIsNotRetained(t *testing.T) {
	r, done := coordServing(t,
		`{"`+testMerkle+`":{"status":"uncovered","reclaimable":true,"contracted":false,"reason":"contract_expired"}}`)
	defer done()

	notReclaimable, _, err := r.Recheck(context.Background(), testMerkle)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if notReclaimable {
		t.Fatal("expired paid account must not be retained; GC must still be able to reclaim")
	}
}

// TestMayReclaim_PrefersRetainedOverContracted pins the accessor:
// when both fields are present and disagree, `retained` wins.
func TestMayReclaim_PrefersRetainedOverContracted(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		rs       coverage.RootStatus
		want     bool
		wantSent bool
	}{
		{"reclaimable=false beats contracted=false",
			coverage.RootStatus{Reclaimable: &no, Contracted: false}, false, true},
		{"reclaimable=true beats contracted=true",
			coverage.RootStatus{Reclaimable: &yes, Contracted: true}, true, true},
		{"absent reclaimable falls back to !contracted",
			coverage.RootStatus{Contracted: true}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rs.MayReclaim(); got != tc.want {
				t.Errorf("MayReclaim = %v, want %v", got, tc.want)
			}
			if got := tc.rs.CoordSentReclaimable(); got != tc.wantSent {
				t.Errorf("CoordSentReclaimable = %v, want %v", got, tc.wantSent)
			}
		})
	}
}

// TestSweeper_DoesNotUnlinkRetainedNonContracted is the end-to-end form:
// a quarantined object whose account is retained-but-not-contracted must
// be RESTORED, not unlinked, even though its quarantine timer expired
// long ago. This is precisely the storage1 situation — 1,171 objects
// sitting in quarantine for 37 days.
func TestSweeper_DoesNotUnlinkRetainedNonContracted(t *testing.T) {
	f := newFixture(t)
	rech, done := coordServing(t,
		`{"`+testMerkle+`":{"status":"covered","reclaimable":false,"contracted":false}}`)
	defer done()

	s, err := NewSweeper(SweeperOpts{
		Config: Config{Enabled: true, RetentionNonContractedHours: 168,
			QuarantineHours: 24, SweepIntervalHours: 24},
		Coverage:   f.store,
		Quarantine: f.quarantine,
		Rechecker:  rech, // the REAL rechecker, not the fake
		Storage:    f.storage,
		Now:        func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatalf("NewSweeper: %v", err)
	}

	// Seed the object and quarantine it 40 days ago: the timer is long
	// expired, so only the predicate can save it.
	quarantinedAt := f.now.Add(-40 * 24 * time.Hour)
	f.putNonContracted(testMerkle, quarantinedAt)
	if err := f.quarantine.MoveToQuarantine(testMerkle, quarantinedAt); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}

	if err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if n := s.Metrics().Unlinked.Load(); n != 0 {
		t.Fatalf("unlinked %d object(s) belonging to a RETAINED account — "+
			"the 2026-07-31 incident reproduced", n)
	}
	if !f.quarantine.IsInObjects(testMerkle) {
		t.Error("retained object should have been RESTORED to objects/ by the recheck")
	}
}
