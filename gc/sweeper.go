package gc

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/obsideo/obsideo-provider/coverage"
	"github.com/obsideo/obsideo-provider/store"
)

// CoverageRechecker is the recheck-before-delete seam GC uses for every
// destructive transition. The sweeper depends on this interface, not on
// *coverage.Client directly, so tests can inject a fake. Production code
// wires the real client through CoverageRecheckerFromClient (see below).
//
// Intentionally narrower than *coverage.Client.QueryRoots: GC asks one
// merkle at a time at the destructive point, because the population
// here is small (only objects that already passed retention) and
// per-object isolation makes coord-blip handling trivial — one failure
// does not poison the whole sweep cycle.
//
// Recheck returns the live `contracted` bool from the coord, or wraps
// ErrRecheckUnusable with a reason label when no usable answer was
// obtained. GC's candidate predicate is `!contracted`; the orthogonal
// `covered`/`uncovered` Status is not consulted at the recheck point.
//
// Outcomes:
//
//   - (contracted, "", nil)    — coord answered authoritatively.
//   - (_, reason, ErrRecheckUnusable wrapped) — answer not usable
//     (network/timeout/5xx/parse). Sweeper increments
//     gc_recheck_failures_total and skips.
//
// Returning a value without an error always means "this answer was
// live, parsed, and authoritative." Production code never returns a
// cached value here.
type CoverageRechecker interface {
	Recheck(ctx context.Context, merkleHex string) (contracted bool, reason string, err error)
}

// ErrRecheckUnusable is the sentinel a CoverageRechecker wraps when the
// coord query did not yield a usable answer. The wrapping error carries
// the failure reason as a metric label (network|timeout|5xx|parse).
var ErrRecheckUnusable = errors.New("coverage recheck did not yield a usable answer")

// rechecker is the production wiring of CoverageRechecker over the
// existing *coverage.Client. It issues a per-merkle QueryRoots call
// and translates the existing error taxonomy into the recheck-failure
// reasons GC needs for its metric labels.
//
// We intentionally re-use the existing client (which already has
// retry/backoff handling) rather than build a parallel HTTP path. That
// keeps the auth, retry, and TLS settings honored uniformly across the
// provider's coord interactions.
type clientRechecker struct {
	client *coverage.Client
}

// CoverageRecheckerFromClient wraps a *coverage.Client into a
// CoverageRechecker for production use. nil client returns nil so
// start.go can wire it conditionally without splitting the call site.
func CoverageRecheckerFromClient(c *coverage.Client) CoverageRechecker {
	if c == nil {
		return nil
	}
	return &clientRechecker{client: c}
}

// Recheck performs the per-merkle live query and translates the
// *coverage.Client error space into a metric-label reason. The
// translation is best-effort: error messages from net/http are not
// stable contract, so we look at structural hints (timeout-classifying
// the error chain, status-code hint in the error string, etc.).
//
// "parse" is the residual category — anything that isn't network or
// timeout or 5xx but still isn't a usable answer.
func (r *clientRechecker) Recheck(ctx context.Context, merkleHex string) (bool, string, error) {
	resp, err := r.client.QueryRoots(ctx, []string{merkleHex})
	if err != nil {
		return false, classifyRecheckError(err), wrapUnusable(err)
	}
	rs, ok := resp[merkleHex]
	if !ok {
		// Coord 2xx'd but did not include the root in the response.
		// Treat as parse-class: the answer is structurally not usable.
		return false, "parse", wrapUnusable(errors.New("coord response missing requested merkle"))
	}
	return rs.Contracted, "", nil
}

// classifyRecheckError maps a *coverage.Client error into one of the
// metric label values from GC_DESIGN.md §10:
// {"network","timeout","5xx","parse"}. Coord-side 4xx is not in the
// list because design §5 treats unreachable/5xx/network/timeout/parse
// as "no delete"; the existing client already returns ErrNonRetryable
// for 4xx so we surface those as parse (an authentication or schema
// problem the operator needs to investigate, not a coord-blip retry).
func classifyRecheckError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, coverage.ErrNonRetryable) {
		return "parse"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Client.Timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "coord 5"):
		return "5xx"
	case strings.Contains(msg, "decode response"):
		return "parse"
	default:
		return "network"
	}
}

func wrapUnusable(inner error) error {
	if inner == nil {
		return ErrRecheckUnusable
	}
	return &recheckErr{inner: inner}
}

type recheckErr struct{ inner error }

func (e *recheckErr) Error() string {
	return ErrRecheckUnusable.Error() + ": " + e.inner.Error()
}
func (e *recheckErr) Unwrap() error { return e.inner }
func (e *recheckErr) Is(target error) bool {
	return target == ErrRecheckUnusable
}

// CoverageReader is the read-side seam over the local coverage cache.
// In production this is *store.Store. The sweeper takes the narrow
// interface so tests can stub coverage state without spinning up a
// full Store.
//
// UpdateCoverage is included so the sweeper can write a fresh covered
// answer back to the cache at restore time — this clears
// first_seen_uncovered and prevents the next sweep from re-firing the
// recheck-vs-cache discrepancy in a loop. The store's UpdateCoverage
// is the canonical site for the transition rules.
type CoverageReader interface {
	List() ([]string, error)
	GetCoverage(merkleHex string) (*store.Coverage, error)
	UpdateCoverage(merkleHex string, answer store.CoverageAnswer, now time.Time) error
}

// Storage is the seam GC uses to clean up the live store records when a
// quarantine entry is finally unlinked. We do not touch index/ownership
// during the move-to-quarantine step (those bytes are part of the
// rollback surface), but at terminal-deletion time we want the index/,
// ownership/, and coverage/ records gone too — otherwise the next
// challenge response leaks orphaned metadata.
//
// In production this is *store.Store via DeleteIndexAndOwnership (a
// thin helper added to the store package).
type Storage interface {
	DeleteIndexAndOwnership(merkleHex string) error
	DeleteCoverage(merkleHex string) error
}

// Metrics holds the in-memory counters and gauges named in
// GC_DESIGN.md §10. The provider does not yet have a Prometheus
// registry; this struct is the interim home so values are exposed for
// internal logging and testing, and a future prom export hooks in by
// snapshotting these atomics.
//
// Counter discipline: monotonic increment only; never decrement. Reset
// only by process restart. Gauges are recomputed each sweep cycle.
type Metrics struct {
	SweepsOK            atomic.Uint64
	SweepsError         atomic.Uint64
	CandidatesSeen      atomic.Uint64
	MarkedUncontracted  atomic.Uint64
	Quarantined         atomic.Uint64
	Unlinked            atomic.Uint64
	Recovered           atomic.Uint64
	RecheckNetwork      atomic.Uint64
	RecheckTimeout      atomic.Uint64
	Recheck5xx          atomic.Uint64
	RecheckParse        atomic.Uint64

	// Gauges are simple atomics; they are overwritten each sweep so
	// callers reading mid-sweep see either the prior or the new value
	// but never a torn read.
	GaugeMarkedUncontracted atomic.Int64
	GaugeQuarantined        atomic.Int64
	GaugeQuarantineBytes    atomic.Int64
}

// IncRecheckFailure dispatches a recheck failure into the right
// reason-labeled counter. Centralised here so callers only have to
// know the reason string from classifyRecheckError.
func (m *Metrics) IncRecheckFailure(reason string) {
	switch reason {
	case "network":
		m.RecheckNetwork.Add(1)
	case "timeout":
		m.RecheckTimeout.Add(1)
	case "5xx":
		m.Recheck5xx.Add(1)
	case "parse":
		m.RecheckParse.Add(1)
	}
}

// Sweeper is the GC state-machine driver. One Sweeper per provider
// process. Constructed via NewSweeper, started via Start, stopped via
// context cancel. Safe to construct without starting (tests).
type Sweeper struct {
	cfg        Config
	cov        CoverageReader
	quarantine *Quarantine
	rechecker  CoverageRechecker
	storage    Storage
	now        func() time.Time
	logger     *log.Logger
	metrics    *Metrics

	// ticker control: NewTicker is wrapped so tests can drive the loop
	// manually via RunOnce instead of waiting on real durations.
	mu sync.Mutex
}

// SweeperOpts is the constructor argument bundle. Required fields are
// non-zero; optional ones default sensibly. We avoid functional-options
// to keep the call site one-line-grep-able from cmd/start.go.
type SweeperOpts struct {
	Config     Config
	Coverage   CoverageReader
	Quarantine *Quarantine
	Rechecker  CoverageRechecker
	Storage    Storage

	// Now is the wall-clock source. Tests inject a fake; production
	// passes nil and gets time.Now().UTC.
	Now func() time.Time

	// Logger is optional; nil uses the package-level log.
	Logger *log.Logger

	// Metrics is optional; nil constructs a fresh Metrics, which is
	// almost always what the production caller wants.
	Metrics *Metrics
}

// NewSweeper builds a Sweeper. Validates the SweeperOpts shape — a nil
// rechecker would be silently catastrophic (every destructive step
// would panic) so we fail loudly at construction time. The opts.Config
// is assumed pre-validated by the config loader; we re-check Enabled
// only because Start short-circuits when the sweeper is disabled.
func NewSweeper(opts SweeperOpts) (*Sweeper, error) {
	if opts.Coverage == nil {
		return nil, errors.New("gc: SweeperOpts.Coverage is required")
	}
	if opts.Quarantine == nil {
		return nil, errors.New("gc: SweeperOpts.Quarantine is required")
	}
	if opts.Rechecker == nil {
		return nil, errors.New("gc: SweeperOpts.Rechecker is required (recheck-before-delete is unconditional)")
	}
	if opts.Storage == nil {
		return nil, errors.New("gc: SweeperOpts.Storage is required")
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	metrics := opts.Metrics
	if metrics == nil {
		metrics = &Metrics{}
	}
	return &Sweeper{
		cfg:        opts.Config,
		cov:        opts.Coverage,
		quarantine: opts.Quarantine,
		rechecker:  opts.Rechecker,
		storage:    opts.Storage,
		now:        now,
		logger:     opts.Logger,
		metrics:    metrics,
	}, nil
}

// Metrics returns the live metrics struct. Callers (tests, future
// metrics-export wiring) read counters from this; nothing should write
// to it from outside the sweeper.
func (s *Sweeper) Metrics() *Metrics { return s.metrics }

// Start runs the sweeper loop until ctx is canceled. The first cycle
// runs immediately on Start (matching the coverage refresher pattern)
// so an operator who turns GC on doesn't have to wait one full
// sweep_interval before any work happens. Subsequent cycles wait one
// sweep_interval between completions.
//
// Start does not return until ctx.Done(). If Enabled is false, Start
// returns immediately — guarding the goroutine spawn at the call site
// is the conventional pattern but a defensive check here means a
// future caller can't accidentally start a disabled sweeper.
func (s *Sweeper) Start(ctx context.Context) {
	if !s.cfg.Enabled {
		s.logf("gc: disabled; sweeper not started")
		return
	}
	s.logf("gc: sweeper started (interval=%s, retention=%s, quarantine=%s)",
		s.cfg.SweepInterval(), s.cfg.RetentionNonContracted(), s.cfg.Quarantine())

	// First tick immediately.
	if err := s.RunOnce(ctx); err != nil {
		s.logf("gc: initial sweep failed: %v", err)
	}
	t := time.NewTicker(s.cfg.SweepInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logf("gc: sweeper stopping: %v", ctx.Err())
			return
		case <-t.C:
			if err := s.RunOnce(ctx); err != nil {
				s.logf("gc: sweep failed: %v", err)
			}
		}
	}
}

// RunOnce executes a single sweep cycle. Public so tests can drive the
// loop deterministically without ticker arithmetic.
//
// Returns a non-nil error only on systemic failures (cannot list the
// store, cannot read quarantine). Per-object failures (recheck
// uncertain, rename failed) are logged + counted and do not abort the
// rest of the cycle.
func (s *Sweeper) RunOnce(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	candidatesSeen := uint64(0)
	defer func() {
		s.metrics.CandidatesSeen.Add(candidatesSeen)
	}()

	now := s.now()
	retention := s.cfg.RetentionNonContracted()
	quarantineWindow := s.cfg.Quarantine()

	// Phase 1: scan quarantine/ first so a flip-back-to-contracted or a
	// quarantine-window-elapsed gets handled before we re-process the
	// objects/ tree. This ordering prevents a freshly-recovered file
	// from being re-quarantined in the same cycle.
	qEntries, err := s.quarantine.ListQuarantined()
	if err != nil {
		s.metrics.SweepsError.Add(1)
		return err
	}
	gaugeQEntries := int64(len(qEntries))
	gaugeQBytes := int64(0)

	for _, e := range qEntries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		gaugeQBytes += e.Bytes
		candidatesSeen++

		// Live recheck FIRST. A quarantined object that flipped back to
		// contracted must be restored regardless of the timer.
		contracted, reason, err := s.rechecker.Recheck(ctx, e.MerkleHex)
		if err != nil {
			s.metrics.IncRecheckFailure(reason)
			s.logf("gc: recheck failed merkle=%s reason=%s err=%v, skipping this cycle", e.MerkleHex, reason, err)
			continue
		}
		if contracted {
			// Mid-window pay (design §11.3): account is contracted
			// again while file sat in quarantine. Restore.
			if err := s.quarantine.RestoreFromQuarantine(e.MerkleHex); err != nil {
				s.logf("gc: restore from quarantine failed merkle=%s: %v", e.MerkleHex, err)
				continue
			}
			// Clear the cache's first_seen_non_contracted by writing
			// the fresh contracted answer through. The store's
			// UpdateCoverage transition rules handle the marker reset;
			// if this write fails the next refresher cycle picks it
			// up, so we log and continue rather than rolling back the
			// rename.
			if err := s.cov.UpdateCoverage(e.MerkleHex, store.CoverageAnswer{
				Status:     store.CoverageStatusCovered,
				Contracted: true,
			}, now); err != nil {
				s.logf("gc: update coverage cache after restore failed merkle=%s: %v", e.MerkleHex, err)
			}
			s.metrics.Recovered.Add(1)
			s.logf("gc: recovered merkle=%s from quarantine, account is contracted again", e.MerkleHex)
			gaugeQEntries--
			gaugeQBytes -= e.Bytes
			continue
		}

		// Still non-contracted. Has the quarantine window elapsed?
		age := now.Sub(e.QuarantinedAt)
		if age < quarantineWindow {
			continue
		}
		// Timer elapsed AND recheck still non-contracted: terminal unlink.
		if err := s.quarantine.UnlinkFromQuarantine(e.MerkleHex); err != nil {
			s.logf("gc: unlink failed merkle=%s: %v", e.MerkleHex, err)
			continue
		}
		// Best-effort cleanup of index/ownership/coverage. A failure
		// here is logged but not fatal — the bytes are gone, which is
		// the correctness-relevant side effect.
		if err := s.storage.DeleteIndexAndOwnership(e.MerkleHex); err != nil {
			s.logf("gc: cleanup index/ownership failed merkle=%s: %v", e.MerkleHex, err)
		}
		if err := s.storage.DeleteCoverage(e.MerkleHex); err != nil {
			s.logf("gc: cleanup coverage failed merkle=%s: %v", e.MerkleHex, err)
		}
		s.metrics.Unlinked.Add(1)
		gaugeQEntries--
		gaugeQBytes -= e.Bytes
		s.logf("gc: confirmed non-contracted, unlinking merkle=%s bytes=%d age=%s",
			e.MerkleHex, e.Bytes, age.Truncate(time.Minute))
	}

	// Phase 2: scan objects/ for marked_uncontracted → eligible →
	// quarantined transitions. Read candidates from the local coverage
	// cache.
	roots, err := s.cov.List()
	if err != nil {
		s.metrics.SweepsError.Add(1)
		return err
	}

	gaugeMarked := int64(0)
	for _, root := range roots {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Read cached coverage. If missing, the refresher hasn't
		// classified this root yet; treat as contracted (do nothing).
		// This is the "retain on missing cache" rule from design §6.
		cov, err := s.cov.GetCoverage(root)
		if err != nil {
			// store.ErrNotFound or read error: treat as no-info, skip.
			continue
		}
		if cov.Contracted {
			// contracted → nothing to do. If first_seen_non_contracted
			// is set here, store.UpdateCoverage already cleared it on
			// the contracted transition.
			continue
		}

		// Non-contracted. The first_seen_non_contracted marker is
		// authoritative for the window calculation. If it's missing
		// (cache wrote contracted=false but somehow no marker), treat
		// as freshly observed at "now" — store.UpdateCoverage normally
		// sets it, so this is a defensive fallback.
		var firstSeen time.Time
		if cov.FirstSeenNonContracted != nil {
			firstSeen = *cov.FirstSeenNonContracted
		} else {
			firstSeen = now
		}

		// Operator-restoration detection (design §11.6): if the file
		// is in objects/ but its mtime is more recent than
		// first_seen_non_contracted, the operator probably moved it
		// back from quarantine. Anchor the timer at the file's mtime
		// so we don't immediately re-quarantine a file the operator
		// just rescued.
		mt, mtErr := s.quarantine.ObjectMtime(root)
		if mtErr == nil && mt.After(firstSeen) {
			firstSeen = mt
		}

		age := now.Sub(firstSeen)
		gaugeMarked++
		candidatesSeen++

		if age < retention {
			// marked_uncontracted, still inside the safety window.
			continue
		}

		// eligible: live recheck before any destructive action.
		contracted, reason, err := s.rechecker.Recheck(ctx, root)
		if err != nil {
			s.metrics.IncRecheckFailure(reason)
			s.logf("gc: recheck failed merkle=%s reason=%s err=%v, skipping this cycle", root, reason, err)
			continue
		}
		if contracted {
			// Stale-cache safety (design §11.5): cache said
			// non-contracted, live coord says contracted. Skip and let
			// the next refresher cycle update the cache.
			s.logf("gc: live recheck says contracted, leaving merkle=%s alone (stale cache)", root)
			continue
		}

		// Capture size before the move so we can update the
		// quarantine-bytes gauge to reflect post-move state. If the
		// stat fails, log and skip — same race the rename would hit.
		size, sizeErr := s.quarantine.ObjectSize(root)
		if sizeErr != nil {
			if errors.Is(sizeErr, ErrNotInObjects) {
				s.logf("gc: object vanished before quarantine merkle=%s: %v", root, sizeErr)
				continue
			}
			s.logf("gc: stat-before-quarantine failed merkle=%s: %v", root, sizeErr)
			continue
		}

		// Live recheck still non-contracted → move to quarantine.
		if err := s.quarantine.MoveToQuarantine(root, now); err != nil {
			if errors.Is(err, ErrNotInObjects) {
				// Race: object disappeared from objects/ between List
				// and rename. Logged but not fatal.
				s.logf("gc: object vanished before quarantine merkle=%s: %v", root, err)
				continue
			}
			s.logf("gc: move-to-quarantine failed merkle=%s: %v", root, err)
			continue
		}
		s.metrics.Quarantined.Add(1)
		s.logf("gc: confirmed non-contracted, moving to quarantine merkle=%s age=%s", root, age.Truncate(time.Minute))
		gaugeMarked--
		gaugeQEntries++
		gaugeQBytes += size
	}

	s.metrics.GaugeMarkedUncontracted.Store(gaugeMarked)
	s.metrics.GaugeQuarantined.Store(gaugeQEntries)
	s.metrics.GaugeQuarantineBytes.Store(gaugeQBytes)
	s.metrics.SweepsOK.Add(1)

	if candidatesSeen == 0 {
		s.logf("gc: sweep complete, candidates=0")
	} else {
		s.logf("gc: sweep complete candidates=%d marked=%d quarantined=%d quarantine_bytes=%d",
			candidatesSeen, gaugeMarked, gaugeQEntries, gaugeQBytes)
	}
	return nil
}

func (s *Sweeper) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// --- Optional convenience constructor for production wiring ---

// DefaultClient returns a *coverage.Client configured for the GC
// recheck path: short timeout, single-attempt-no-retry behavior. We
// reuse the existing coverage.Client so auth headers and TLS settings
// match the refresher exactly. A non-zero MaxRetries here would make
// the recheck path slower than necessary (we'd rather skip-and-retry
// next cycle than block the sweeper goroutine on a bad coord).
//
// httpClient is required (caller picks the timeout); coordURL and
// apiKey come from the provider config.
func DefaultClient(coordURL, apiKey string, httpClient *http.Client) *coverage.Client {
	c := coverage.NewClient(coordURL, apiKey, httpClient)
	// Single attempt — sweeper-level retry is "skip this cycle, try
	// next" and is the right granularity for "coord blip => no delete."
	c.MaxRetries = 0
	return c
}
