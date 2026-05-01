package gc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Quarantine layout:
//
//	{data_dir}/objects/<merkle_hex>          (live)
//	{data_dir}/quarantine/<merkle_hex>       (pending unlink)
//
// We keep the merkle filename identical between the two locations so an
// operator who manually moves a file back into objects/ does not have
// to rename it. The on-disk mtime of the quarantine entry is the
// quarantine-start timestamp — there is no sidecar bookkeeping file.
// Reconstructing timers from mtime survives both crashes and external
// tooling that touched the file (which is fine: an external touch is an
// implicit "reset the clock," and that is the right behavior since
// whoever touched it almost certainly intended to interact with it).
//
// Atomic-rename only. We rely on os.Rename being atomic within a single
// filesystem on POSIX, and best-effort-near-atomic on Windows. We do
// NOT implement a copy-then-delete fallback — the design says rename
// only, and a copy-then-delete here would silently double the disk
// footprint of an in-flight quarantine operation and weaken the
// "partial-state-on-crash bounded by atomic rename" guarantee.

// objectsSubdir and quarantineSubdir are the on-disk subdirectory names
// the GC package owns. We re-derive them from the data dir rather than
// taking a *store.Store dependency to keep the package boundary clean —
// store.Store does not (and per the design should not) know about
// quarantine.
const (
	objectsSubdir    = "objects"
	quarantineSubdir = "quarantine"
)

// Quarantine is the filesystem primitive set GC uses to move files
// between the live objects/ tree and the sibling quarantine/ tree, and
// to introspect the quarantine view for operator-facing concerns.
//
// Quarantine takes the data dir (not a *store.Store) deliberately: the
// store package is the canonical owner of objects/, but GC owns
// quarantine/, and crossing into store.Delete would also unlink the
// index/ownership files which we explicitly do not want to do until the
// final unlink step. Keeping the rename surface inside this package
// makes the boundary obvious.
type Quarantine struct {
	dataDir string
}

// NewQuarantine returns a Quarantine rooted at dataDir, creating the
// quarantine/ subdirectory if it does not exist. Failing to MkdirAll is
// a hard startup error; without the directory the sweeper cannot
// function and silent fallback would mask the problem.
func NewQuarantine(dataDir string) (*Quarantine, error) {
	q := &Quarantine{dataDir: dataDir}
	if err := os.MkdirAll(q.quarantineRoot(), 0o755); err != nil {
		return nil, fmt.Errorf("create quarantine dir: %w", err)
	}
	// objects/ should already exist (store.New creates it), but if a
	// caller wires us up before the store, MkdirAll is a no-op so this
	// is safe to do anyway.
	if err := os.MkdirAll(q.objectsRoot(), 0o755); err != nil {
		return nil, fmt.Errorf("create objects dir: %w", err)
	}
	return q, nil
}

func (q *Quarantine) objectsRoot() string {
	return filepath.Join(q.dataDir, objectsSubdir)
}

func (q *Quarantine) quarantineRoot() string {
	return filepath.Join(q.dataDir, quarantineSubdir)
}

// objectPath is the path the live store uses for merkleHex. Mirrors
// store.Store.objPath; duplicated here rather than imported because
// store.Store does not export it. If the path scheme ever changes,
// this duplication is a one-line update.
func (q *Quarantine) objectPath(merkleHex string) string {
	return filepath.Join(q.objectsRoot(), merkleHex)
}

func (q *Quarantine) quarantinePath(merkleHex string) string {
	return filepath.Join(q.quarantineRoot(), merkleHex)
}

// MoveToQuarantine atomically renames the object file from objects/ to
// quarantine/. The mtime is reset to `now` so the quarantine timer
// starts from the move, not from whatever the original file mtime was.
//
// Returns ErrNotInObjects if there is no live object at the source. We
// treat that as a recoverable race rather than a hard error: another
// goroutine (or the operator) might have already moved or removed the
// file. The sweeper logs and skips.
//
// We deliberately do NOT touch index/, ownership/, or coverage/ here.
// Those are the live store's domain; GC interacting with them on a
// quarantine move would (a) prevent operator restoration via plain
// `mv` since restoring would leave them missing, and (b) blur the
// rollback boundary. They are cleaned up only at final unlink time.
func (q *Quarantine) MoveToQuarantine(merkleHex string, now time.Time) error {
	src := q.objectPath(merkleHex)
	dst := q.quarantinePath(merkleHex)

	// Target dir already exists from NewQuarantine, but a paranoid
	// MkdirAll here means tests that construct Quarantine directly
	// without calling the constructor still work.
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("ensure quarantine dir: %w", err)
	}

	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotInObjects
		}
		return fmt.Errorf("stat source: %w", err)
	}

	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("rename to quarantine: %w", err)
	}
	// Set mtime to now so the quarantine timer is anchored at the move
	// time. If this fails after the rename, the file IS in quarantine
	// with whatever mtime it had — we log but don't unwind, because
	// unwinding would itself need a rename and could fail in the same
	// way. Worst case the timer is anchored slightly earlier than now,
	// which makes the file eligible for unlink slightly sooner — that
	// is bounded and not a correctness violation.
	if err := os.Chtimes(dst, now, now); err != nil {
		return fmt.Errorf("set quarantine mtime: %w", err)
	}
	return nil
}

// RestoreFromQuarantine atomically renames the file from quarantine/
// back to objects/. Used both by the sweeper (account flipped to
// contracted while file was in quarantine) and conceptually by an
// operator (though the operator typically uses plain `mv` outside this
// process).
//
// Returns ErrNotInQuarantine if no quarantine entry exists.
func (q *Quarantine) RestoreFromQuarantine(merkleHex string) error {
	src := q.quarantinePath(merkleHex)
	dst := q.objectPath(merkleHex)

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("ensure objects dir: %w", err)
	}
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotInQuarantine
		}
		return fmt.Errorf("stat quarantine source: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("rename from quarantine: %w", err)
	}
	return nil
}

// UnlinkFromQuarantine removes the quarantine entry permanently. This
// is the terminal step of the GC state machine; after this call the
// bytes are gone and the design's "deleted" state is reached.
//
// Returns ErrNotInQuarantine if no entry exists. We do not treat
// "already gone" as an error in any other helper, but Unlink is the
// destructive step we want the caller to be sure happened — silent
// success on a missing file would obscure a race with another GC
// instance or external tooling.
func (q *Quarantine) UnlinkFromQuarantine(merkleHex string) error {
	src := q.quarantinePath(merkleHex)
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrNotInQuarantine
		}
		return fmt.Errorf("stat quarantine entry: %w", err)
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("unlink quarantine entry: %w", err)
	}
	return nil
}

// QuarantineEntry is the minimal description of one quarantined merkle
// root surfaced to the sweeper and (transitively) to operator logging.
// Bytes is read from FileInfo at scan time so the operator gets a
// realistic disk-pressure number; we do not cache it.
type QuarantineEntry struct {
	MerkleHex     string
	QuarantinedAt time.Time
	Bytes         int64
}

// ListQuarantined returns every entry currently in quarantine/, sorted
// by merkle hex for stable test output. mtime is read from the inode,
// so this is the timer-reconstruction path used both at startup and
// during normal sweeps. We skip non-hex names defensively — anything an
// operator dropped in there by hand that is not a merkle hash gets
// ignored rather than crashing the sweeper.
func (q *Quarantine) ListQuarantined() ([]QuarantineEntry, error) {
	entries, err := os.ReadDir(q.quarantineRoot())
	if err != nil {
		// Missing root is treated as "no entries" rather than an error,
		// because the sweeper calls this every cycle and a freshly
		// initialised data dir might not have written anything yet.
		// NewQuarantine creates the dir, but defensive callers may not
		// go through the constructor.
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read quarantine dir: %w", err)
	}

	out := make([]QuarantineEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isHexName(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			// Race with operator deletion; skip and move on. Logging
			// belongs to the sweeper layer, not the filesystem helper.
			continue
		}
		out = append(out, QuarantineEntry{
			MerkleHex:     name,
			QuarantinedAt: info.ModTime(),
			Bytes:         info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].MerkleHex < out[j].MerkleHex
	})
	return out, nil
}

// IsInObjects reports whether merkleHex is present in the live objects/
// tree. Used by the sweeper to detect operator restoration (file
// manually moved out of quarantine) — design §11 scenario 6.
func (q *Quarantine) IsInObjects(merkleHex string) bool {
	_, err := os.Stat(q.objectPath(merkleHex))
	return err == nil
}

// IsInQuarantine reports whether merkleHex is present in the quarantine
// tree. Symmetric counterpart to IsInObjects; used to verify state
// before destructive actions.
func (q *Quarantine) IsInQuarantine(merkleHex string) bool {
	_, err := os.Stat(q.quarantinePath(merkleHex))
	return err == nil
}

// ObjectMtime returns the mtime of the live object file. Used by the
// sweeper to anchor the marked_uncovered timer for a file that was
// manually restored from quarantine — design §11 scenario 6. Returns
// ErrNotInObjects if the file does not exist.
func (q *Quarantine) ObjectMtime(merkleHex string) (time.Time, error) {
	info, err := os.Stat(q.objectPath(merkleHex))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, ErrNotInObjects
		}
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// ObjectSize returns the size in bytes of the live object file. Used by
// the sweeper to update the quarantine-bytes gauge when Phase 2 moves a
// file into quarantine. Returns ErrNotInObjects if the file is gone.
func (q *Quarantine) ObjectSize(merkleHex string) (int64, error) {
	info, err := os.Stat(q.objectPath(merkleHex))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, ErrNotInObjects
		}
		return 0, err
	}
	return info.Size(), nil
}

// ErrNotInObjects is returned when a quarantine operation expected the
// file to exist in objects/ and it did not. Distinct from
// ErrNotInQuarantine so callers can distinguish the two race conditions
// (operator pulled file out vs. file already unlinked).
var ErrNotInObjects = errors.New("merkle not in objects/")

// ErrNotInQuarantine is returned when a quarantine operation expected
// the file to be in quarantine/ and it was not.
var ErrNotInQuarantine = errors.New("merkle not in quarantine/")

// isHexName matches the predicate store.isHexName uses: 1+ hex chars,
// any case. Duplicated rather than exported from store/ because the
// store version is unexported and we want to keep this helper local
// to whatever rules quarantine wants for operator-dropped files.
func isHexName(s string) bool {
	if s == "" {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
	}) == -1
}
