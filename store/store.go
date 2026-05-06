// Package store implements plain-filesystem object storage for obsideo-provider.
//
// Layout:
//
//	{data_dir}/objects/{merkle_hex}         raw file bytes
//	{data_dir}/index/{merkle_hex}.json      {"chunk_size":N,"total_chunks":N,"chunk_hashes":["hex",...]}
//	{data_dir}/ownership/{merkle_hex}.json  v2.1: {"owner_pubkey","owner_sig_pubkey","received_at"}
//
// The ownership file is write-once-immutable per docs/retention_authority_design.md §9.1.
// It is created with mode 0o444 so any accidental mutation hits EPERM at the
// OS layer. Files are written only when the upload token carries both owner
// pubkeys; legacy-account uploads skip the write entirely per design §9.2.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Index holds per-object metadata needed to answer challenge requests.
type Index struct {
	ChunkSize   int      `json:"chunk_size"`
	TotalChunks int      `json:"total_chunks"`
	ChunkHashes []string `json:"chunk_hashes"` // hex-encoded sha256(fmt.Sprintf("%d%x", i, chunk))
}

// Ownership is the per-merkle-root record of who authorized the upload.
// Written once at upload time from the coord-issued upload token's claims;
// never rewritten. Used by the user-signed delete handler to verify Ed25519
// signatures against OwnerSigPubkey. See docs/retention_authority_design.md §6.1, §9.1.
type Ownership struct {
	OwnerPubkey    string    `json:"owner_pubkey"`     // obk_pub_<43 b64url>, X25519
	OwnerSigPubkey string    `json:"owner_sig_pubkey"` // obk_sig_<43 b64url>, Ed25519
	ReceivedAt     time.Time `json:"received_at"`
}

// CoverageAnswer is the per-root response from the coordinator's
// /v1/provider/roots/status endpoint. Matches the wire shape on the
// coord side (api.RootStatus). Stored in the provider's local coverage
// cache alongside tracking state the provider owns.
//
// Two orthogonal signals: Status answers serveability (covered for
// paid + testdrive + enterprise when active+unexpired). Contracted
// answers payment ("provider being paid right now?" — paid + active +
// ExpiresAt > now only). GC consumes Contracted; existing refresher
// and challenge code continue to consume Status.
type CoverageAnswer struct {
	Status     string `json:"status"`           // "covered" | "uncovered" | "orphaned"
	Contracted bool   `json:"contracted"`       // paid + active + ExpiresAt > now
	Until      string `json:"until,omitempty"`  // RFC 3339 UTC, present only for paid-covered
	Reason     string `json:"reason,omitempty"` // diagnostic enum from coord
}

// Coverage is the per-merkle-root cached answer plus the local tracking
// state the provider needs to apply grace periods. See
// docs/retention_authority_design.md §4.2, §6.2. Mutable on refresh,
// unlike the write-once Ownership record; stored as
// {data_dir}/coverage/{merkle_hex}.json.
//
// Two transition markers, one per signal:
//
//   - FirstSeenUncovered tracks the first refresh that observed
//     Status != covered. Existing refresher / challenge code uses this.
//
//   - FirstSeenNonContracted tracks the first refresh that observed
//     Contracted == false. GC's retention timer is anchored here. The
//     two timers are independent because the two signals are
//     independent: testdrive flips Contracted false without ever
//     flipping Status uncovered, so the GC timer needs its own anchor.
type Coverage struct {
	Status                 string     `json:"status"`
	Contracted             bool       `json:"contracted"`
	Until                  string     `json:"until,omitempty"`
	Reason                 string     `json:"reason,omitempty"`
	RefreshedAt            time.Time  `json:"refreshed_at"`
	FirstSeenUncovered     *time.Time `json:"first_seen_uncovered,omitempty"`
	FirstSeenNonContracted *time.Time `json:"first_seen_non_contracted,omitempty"`
}

// Coverage status enum values. Duplicated from coord/api/coverage.go to
// avoid an import cycle; providers verify the string matches these
// exactly and treat any other value as "unknown" (retain per design §6.6).
const (
	CoverageStatusCovered   = "covered"
	CoverageStatusUncovered = "uncovered"
	CoverageStatusOrphaned  = "orphaned"
)

const DefaultChunkSize = 1024 * 1024

// Store manages objects on the local filesystem.
type Store struct {
	objDir       string
	indexDir     string
	ownershipDir string
	coverageDir  string
	stagingDir   string
}

// New creates a Store rooted at dataDir, creating subdirectories if needed.
func New(dataDir string) (*Store, error) {
	objDir := filepath.Join(dataDir, "objects")
	idxDir := filepath.Join(dataDir, "index")
	ownDir := filepath.Join(dataDir, "ownership")
	covDir := filepath.Join(dataDir, "coverage")
	stgDir := filepath.Join(dataDir, "staging")
	for _, d := range []string{objDir, idxDir, ownDir, covDir, stgDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("create store dir %s: %w", d, err)
		}
	}
	return &Store{
		objDir:       objDir,
		indexDir:     idxDir,
		ownershipDir: ownDir,
		coverageDir:  covDir,
		stagingDir:   stgDir,
	}, nil
}

// Put stores raw bytes under merkleHex, computing and persisting the chunk index.
// chunkSize determines how bytes are split for Merkle/challenge purposes.
// Writes are atomic (temp file → rename).
func (s *Store) Put(merkleHex string, data []byte, chunkSize int) error {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	// Build chunk hashes.
	idx := buildIndex(data, chunkSize)

	// Write object atomically.
	if err := atomicWrite(s.objPath(merkleHex), data); err != nil {
		return fmt.Errorf("write object: %w", err)
	}

	// Write index atomically.
	idxBytes, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}
	if err := atomicWrite(s.idxPath(merkleHex), idxBytes); err != nil {
		return fmt.Errorf("write index: %w", err)
	}
	return nil
}

// Get returns the raw bytes for merkleHex, or an error if not found.
func (s *Store) Get(merkleHex string) ([]byte, error) {
	data, err := os.ReadFile(s.objPath(merkleHex))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return data, nil
}

// GetIndex returns the stored Index for merkleHex.
func (s *Store) GetIndex(merkleHex string) (*Index, error) {
	data, err := os.ReadFile(s.idxPath(merkleHex))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}
	return &idx, nil
}

// Delete removes the object, its index, any ownership record, and any
// coverage record. Returns nil if the object does not exist. Because
// ownership files are mode 0o444, Remove may fail with EACCES on some
// filesystems; we chmod back to writable before removal so cleanup works
// regardless.
func (s *Store) Delete(merkleHex string) error {
	_ = os.Remove(s.objPath(merkleHex))
	_ = os.Remove(s.idxPath(merkleHex))
	ownPath := s.ownPath(merkleHex)
	if _, err := os.Stat(ownPath); err == nil {
		// Restore write permission before unlinking; mode 0o444 does not
		// prevent unlink on POSIX (unlink checks the parent dir's perms,
		// not the file's), but on Windows the read-only attribute does
		// block delete. Chmod covers both cases.
		_ = os.Chmod(ownPath, 0o644)
		_ = os.Remove(ownPath)
	}
	_ = os.Remove(s.covPath(merkleHex))
	return nil
}

// DeleteIndexAndOwnership removes the index file and any ownership
// record for merkleHex, leaving the object file (if any) untouched.
// Used by the GC package after it has unlinked the object from the
// quarantine tree: the bytes are gone, but the index/ownership records
// would linger and cause stale challenge metadata or confused
// downstream readers. Returns nil if the records do not exist.
//
// Mirrors Delete's behavior re: the 0o444 ownership-mode dance —
// Windows treats read-only files as undeletable, so chmod first then
// remove. Coverage cleanup is the caller's responsibility (GC issues
// DeleteCoverage as a separate call so the coverage record can be
// kept around if the design ever changes).
func (s *Store) DeleteIndexAndOwnership(merkleHex string) error {
	_ = os.Remove(s.idxPath(merkleHex))
	ownPath := s.ownPath(merkleHex)
	if _, err := os.Stat(ownPath); err == nil {
		_ = os.Chmod(ownPath, 0o644)
		_ = os.Remove(ownPath)
	}
	return nil
}

// PutOwnership records the per-merkle-root ownership bundle exactly once.
// Fails with ErrOwnershipExists if an ownership file already exists for
// the given merkle root; this is the write-once-immutable invariant from
// docs/retention_authority_design.md §9.1 (invariant 4). File mode is set
// to 0o444 after write so any accidental mutation hits EPERM at the OS
// layer.
//
// Callers pass a fully-populated Ownership (both pubkeys + received_at).
// If either pubkey string is empty, PutOwnership returns an error rather
// than writing a half-formed record; the upload handler is responsible
// for deciding whether to skip the write for legacy accounts.
func (s *Store) PutOwnership(merkleHex string, own Ownership) error {
	if own.OwnerPubkey == "" || own.OwnerSigPubkey == "" {
		return fmt.Errorf("ownership requires both owner_pubkey and owner_sig_pubkey")
	}
	path := s.ownPath(merkleHex)
	if _, err := os.Stat(path); err == nil {
		return ErrOwnershipExists
	}
	data, err := json.Marshal(own)
	if err != nil {
		return fmt.Errorf("marshal ownership: %w", err)
	}
	if err := atomicWrite(path, data); err != nil {
		return fmt.Errorf("write ownership: %w", err)
	}
	// Enforce immutability at the filesystem layer.
	if err := os.Chmod(path, 0o444); err != nil {
		return fmt.Errorf("chmod ownership to 0o444: %w", err)
	}
	return nil
}

// GetOwnership reads the ownership record for merkleHex. Returns
// ErrNotFound when no ownership file exists (legacy-account uploads and
// pre-Phase-1 data; see design §9.2).
func (s *Store) GetOwnership(merkleHex string) (*Ownership, error) {
	data, err := os.ReadFile(s.ownPath(merkleHex))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var own Ownership
	if err := json.Unmarshal(data, &own); err != nil {
		return nil, fmt.Errorf("parse ownership: %w", err)
	}
	return &own, nil
}

// HasOwnership reports whether an ownership record exists for merkleHex.
// Convenience wrapper; callers needing the bytes should use GetOwnership.
func (s *Store) HasOwnership(merkleHex string) bool {
	_, err := os.Stat(s.ownPath(merkleHex))
	return err == nil
}

// GetCoverage reads the cached coverage record for merkleHex. Returns
// ErrNotFound if the provider has not yet observed an answer for this
// root from the coord.
func (s *Store) GetCoverage(merkleHex string) (*Coverage, error) {
	data, err := os.ReadFile(s.covPath(merkleHex))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var c Coverage
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse coverage: %w", err)
	}
	return &c, nil
}

// UpdateCoverage applies a fresh answer from the coordinator, handling the
// first_seen_uncovered transition marker internally. Callers pass the
// verbatim coord response plus the current time.
//
// Transition rules per docs/retention_authority_design.md §6.2:
//
//   - covered → clear FirstSeenUncovered (a successful renewal or re-cover
//     resets any prior grace-period countdown).
//   - uncovered or orphaned → if FirstSeenUncovered is already set from a
//     prior refresh, preserve it (the grace period continues); otherwise
//     set it to `now`.
//
// The file is rewritten on each call with the new state. Unlike
// ownership/*.json files, coverage/*.json is deliberately mutable.
func (s *Store) UpdateCoverage(merkleHex string, answer CoverageAnswer, now time.Time) error {
	prior, err := s.GetCoverage(merkleHex)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("read prior coverage: %w", err)
	}

	next := Coverage{
		Status:      answer.Status,
		Contracted:  answer.Contracted,
		Until:       answer.Until,
		Reason:      answer.Reason,
		RefreshedAt: now,
	}

	if answer.Status == CoverageStatusCovered {
		// A covered answer resets any grace-period tracking. Old
		// FirstSeenUncovered values are stale and would incorrectly
		// count toward prune eligibility on the next uncovered answer.
		next.FirstSeenUncovered = nil
	} else {
		// uncovered or orphaned (or any unknown status): track when we
		// first saw non-covered so the provider can apply a grace period.
		if prior != nil && prior.FirstSeenUncovered != nil {
			preserved := *prior.FirstSeenUncovered
			next.FirstSeenUncovered = &preserved
		} else {
			t := now
			next.FirstSeenUncovered = &t
		}
	}

	// Independent transition marker for GC's retention timer. Tracks
	// when Contracted first flipped from true to false, regardless of
	// what Status is doing. Testdrive accounts flip Contracted false
	// without their Status ever becoming uncovered, so this anchor has
	// to be tracked separately from FirstSeenUncovered.
	if answer.Contracted {
		next.FirstSeenNonContracted = nil
	} else {
		if prior != nil && prior.FirstSeenNonContracted != nil {
			preserved := *prior.FirstSeenNonContracted
			next.FirstSeenNonContracted = &preserved
		} else {
			t := now
			next.FirstSeenNonContracted = &t
		}
	}

	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("marshal coverage: %w", err)
	}
	if err := atomicWrite(s.covPath(merkleHex), data); err != nil {
		return fmt.Errorf("write coverage: %w", err)
	}
	return nil
}

// DeleteCoverage removes the coverage record for merkleHex. Returns nil
// if the record does not exist. Used when an object is deleted so stale
// coverage state does not linger on disk.
func (s *Store) DeleteCoverage(merkleHex string) error {
	err := os.Remove(s.covPath(merkleHex))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// HasCoverage reports whether a coverage record exists for merkleHex.
func (s *Store) HasCoverage(merkleHex string) bool {
	_, err := os.Stat(s.covPath(merkleHex))
	return err == nil
}

// List returns all stored merkle root hex strings.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.objDir)
	if err != nil {
		return nil, fmt.Errorf("list objects: %w", err)
	}
	roots := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			name := e.Name()
			// Validate: must be a 64-char hex string (32-byte sha256 or sha3-512 prefix)
			if isHexName(name) {
				roots = append(roots, name)
			}
		}
	}
	return roots, nil
}

// ErrNotFound is returned by Get/GetIndex/GetOwnership when the object does not exist.
var ErrNotFound = fmt.Errorf("object not found")

// ErrOwnershipExists is returned by PutOwnership when the target file
// already exists. The write-once-immutable invariant (design §9.1) forbids
// overwriting an existing ownership record; callers receiving this error
// should NOT attempt to work around it, since the existing record is the
// authorizing record for the object.
var ErrOwnershipExists = fmt.Errorf("ownership record already exists for this merkle root")

// --- helpers ---

func (s *Store) objPath(merkleHex string) string {
	return filepath.Join(s.objDir, merkleHex)
}

func (s *Store) idxPath(merkleHex string) string {
	return filepath.Join(s.indexDir, merkleHex+".json")
}

func (s *Store) ownPath(merkleHex string) string {
	return filepath.Join(s.ownershipDir, merkleHex+".json")
}

func (s *Store) covPath(merkleHex string) string {
	return filepath.Join(s.coverageDir, merkleHex+".json")
}

func buildIndex(data []byte, chunkSize int) Index {
	total := (len(data) + chunkSize - 1) / chunkSize
	if total == 0 {
		total = 1
	}
	hashes := make([]string, total)
	for i := 0; i < total; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		// Platform spec: sha256(fmt.Sprintf("%d%x", index, chunk_bytes))
		h := sha256.Sum256([]byte(fmt.Sprintf("%d%x", i, chunk)))
		hashes[i] = hex.EncodeToString(h[:])
	}
	return Index{
		ChunkSize:   chunkSize,
		TotalChunks: total,
		ChunkHashes: hashes,
	}
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

func isHexName(s string) bool {
	if len(s) == 0 {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool {
		return !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'))
	}) == -1
}

// StreamTo writes the object for merkleHex to w. Returns ErrNotFound if absent.
func (s *Store) StreamTo(merkleHex string, w io.Writer) error {
	f, err := os.Open(s.objPath(merkleHex))
	if err != nil {
		if os.IsNotExist(err) {
			return ErrNotFound
		}
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// OpenObject returns a seekable handle to the raw bytes for merkleHex.
// Caller owns the close. Used by the challenge handler to read the
// challenged chunk at offset without loading the whole object into memory.
func (s *Store) OpenObject(merkleHex string) (*os.File, error) {
	f, err := os.Open(s.objPath(merkleHex))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return f, nil
}

// StagingDirPath returns the per-merkle staging directory used by the
// chunked-upload handlers. Caller is expected to MkdirAll it before
// writing the first chunk.
func (s *Store) StagingDirPath(merkleHex string) string {
	return filepath.Join(s.stagingDir, merkleHex)
}

// StagingChunkPath returns the path to the Nth transport chunk in the
// per-merkle staging directory.
func (s *Store) StagingChunkPath(merkleHex string, index int) string {
	return filepath.Join(s.StagingDirPath(merkleHex), fmt.Sprintf("chunk_%05d", index))
}

// StagingMetaPath returns the path to the staging meta file (which
// records the total chunk count for this upload).
func (s *Store) StagingMetaPath(merkleHex string) string {
	return filepath.Join(s.StagingDirPath(merkleHex), "meta")
}

// RemoveStaging deletes the staging directory for merkleHex. Called by
// the finalize handler after the assembled bytes have landed via Put.
// No-op if the directory does not exist.
func (s *Store) RemoveStaging(merkleHex string) error {
	err := os.RemoveAll(s.StagingDirPath(merkleHex))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// UsedBytes returns the total size in bytes of every file under the
// objects/ directory. Used by the heartbeat to report ground-truth
// disk usage to coord — the previous heartbeat hardcoded
// `used_bytes: 0` (see cmd/heartbeat.go pre-2026-05-02), which made
// coord's per-provider disk-pressure tracking and operator-console
// usage display permanently wrong. Walks the directory once per call;
// caller throttles by calling it from the heartbeat tick (~30s
// cadence).
//
// Best-effort: if a file is removed mid-walk (concurrent delete) it's
// silently skipped. Returns the sum and a non-nil error only when the
// objects/ directory itself can't be opened.
func (s *Store) UsedBytes() (int64, error) {
	var total int64
	err := filepath.Walk(s.objDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// File-level read errors (concurrent delete, transient I/O)
			// shouldn't fail the whole walk. The heartbeat would rather
			// report a slightly-stale total than nothing.
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Match List(): only count hex-named files (real objects).
		// Skips the .tmp-* atomic-write intermediates and any junk.
		if isHexName(info.Name()) {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("walk objects: %w", err)
	}
	return total, nil
}

// DiskFreeBytes returns the actual filesystem free space at the data
// directory, queried via the OS (statfs on unix, GetDiskFreeSpaceEx
// on windows). Independent of the operator's declared CapacityBytes
// — answers "what's actually writable RIGHT NOW," which is the number
// the placement layer needs to avoid the Yala-class case where
// declared capacity and writable space drift apart (orphan staging
// cruft, shared filesystem with other workloads, etc.).
//
// Implementation in store_disk_unix.go / store_disk_windows.go via
// build tags. Returns an error if the underlying syscall fails;
// caller (heartbeat tick) treats that as "don't include the field"
// rather than failing the heartbeat outright.
func (s *Store) DiskFreeBytes() (int64, error) {
	return diskFreeAt(s.objDir)
}

// SweepStaleStaging walks the staging/ directory and removes entries
// whose mtime is older than maxAge. Closes the orphan-staging-cruft
// loop that's the most likely cause of operators reporting
// "declared X capacity but full at Y < X" (see Yala 2026-05-02 —
// failed test uploads left ~95 MB of orphan staging per attempt;
// across multiple runs filled an 8 GB disk). Returns the count of
// staging dirs reclaimed and the first error encountered (continues
// past per-entry errors so one bad dir doesn't block the rest).
//
// Caller schedules this from a background ticker (e.g. once per
// hour) in cmd/start.go. maxAge of 1h matches the chunked-upload
// session timeout — anything older than that is genuinely orphaned.
//
// Idempotent: empty staging dir → returns (0, nil). Missing staging
// dir → returns (0, nil) without an error.
func (s *Store) SweepStaleStaging(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(s.stagingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read staging dir: %w", err)
	}
	cutoff := time.Now().Add(-maxAge)
	cleaned := 0
	var firstErr error
	for _, e := range entries {
		// Staging entries are merkle-named directories; skip anything else.
		if !e.IsDir() {
			continue
		}
		if !isHexName(e.Name()) {
			continue
		}
		path := filepath.Join(s.stagingDir, e.Name())
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
		if err := os.RemoveAll(path); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cleaned++
	}
	return cleaned, firstErr
}
