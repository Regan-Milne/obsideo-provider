// Package pausectl implements the retention-authority circuit breaker per
// docs/retention_authority_design.md §4.4 and §6.7.
//
// A pause signal is a canonical-JSON message signed with an offline cold
// key (separate from any coordinator operational key) that tells providers
// to halt all coverage-driven prune decisions. It is not a generic "stop
// the provider" switch: user-signed deletes continue to process, uploads
// continue, downloads continue, and the coverage-refresh loop itself
// continues to update the local cache. The pause only affects decisions
// that would act on coverage answers to prune bytes.
//
// Design invariants enforced here (design §12 item 5, §4.4):
//
//  1. Signature is verified against a cold-key pubkey that is baked
//     into the provider binary at build time (see embedded.go).
//     Runtime rotation is intentionally not supported.
//  2. Sequence numbers are strictly monotonic. A replay of a previously-
//     accepted signal (or an out-of-order signal) is rejected.
//  3. expires_at must lie in the future at verify time. There is no
//     "resume" message; auto-expire via expires_at is the only unpause.
//  4. Only the declared type ("obsideo.pause-signal"), version (1), and
//     scope ("coverage-enforcement") are accepted. Future scopes would
//     require a new binary release.
//
// The stored form on disk ({data_dir}/pause/current.json) preserves the
// verbatim canonical payload bytes so re-verification on restart uses the
// exact byte-sequence that was originally signed, avoiding the
// canonicalization-drift class of bugs.
package pausectl

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SignalType is the only accepted `type` field value.
const SignalType = "obsideo.pause-signal"

// SignalVersion is the only accepted `version` field value.
const SignalVersion = 1

// SignalScope is the only accepted `scope` field value for Phase 1.
// Future scopes require a new binary release per §4.4 design note.
const SignalScope = "coverage-enforcement"

// ColdKeyPrefix matches the obk_sig_ family used elsewhere in the codebase.
const ColdKeyPrefix = "obk_sig_"

// Wire types.

// Envelope is the wire format for an incoming pause signal. Matches the
// pattern established by sdk/src/crypto/sign.ts and api/delete.go: the
// `payload` is the verbatim canonical JSON that was signed; `signature`
// is the detached Ed25519 signature, base64url (no padding).
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Signal is the parsed pause-signal payload per design §4.4.
type Signal struct {
	Type           string `json:"type"`
	Version        int    `json:"version"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
	Scope          string `json:"scope"`
	SequenceNumber int64  `json:"sequence_number"`
	Reason         string `json:"reason"`
}

// StoredPause is the on-disk representation. Preserves the verbatim
// envelope so re-verification after a provider restart uses the same
// bytes that were originally signed, and exposes the parsed Signal for
// operator inspection.
type StoredPause struct {
	Envelope Envelope `json:"envelope"`
	Signal   Signal   `json:"signal"`
}

// Errors. Distinct types so the HTTP layer can map to correct status.

var (
	ErrNotConfigured          = errors.New("circuit breaker not configured")
	ErrInvalidEnvelope        = errors.New("invalid envelope")
	ErrInvalidSignatureFormat = errors.New("invalid signature format")
	ErrInvalidSignature       = errors.New("signature does not verify against cold key")
	ErrInvalidPayload         = errors.New("invalid payload JSON")
	ErrWrongType              = errors.New("wrong signal type")
	ErrWrongVersion           = errors.New("wrong signal version")
	ErrWrongScope             = errors.New("wrong signal scope")
	ErrExpired                = errors.New("expires_at is not in the future")
	ErrMalformedTimestamp     = errors.New("timestamp is not RFC3339")
	ErrSequenceNotMonotonic   = errors.New("sequence_number is not strictly greater than last-seen")
)

// State manages the persistent pause state on disk. Safe for concurrent
// use: Apply and reads are serialised on a single RWMutex. File writes
// are atomic (temp + rename) so a crash mid-Apply cannot leave a partial
// current.json on disk.
type State struct {
	dir       string
	coldKey   ed25519.PublicKey // nil if no cold key configured → pause signals rejected
	mu        sync.RWMutex
	lastSeq   int64        // cached; authoritative value is last_sequence_number on disk
	active    *StoredPause // nil when no active pause
}

const (
	currentFilename = "current.json"
	lastSeqFilename = "last_sequence_number"
	pauseDirname    = "pause"
)

// Load initialises a State rooted at {dataDir}/pause. coldKey may be nil,
// in which case any inbound pause signal is rejected with
// ErrNotConfigured (the provider still runs, just without an active
// circuit breaker — matches the pre-Phase-1 operator case).
//
// If an existing current.json is on disk, Load re-verifies its signature
// against coldKey and re-parses. A file that fails verification is moved
// aside (current.json.rejected-<timestamp>) and treated as no active
// pause. This protects against cold-key rotation or disk corruption
// leaving a provider locked in pause mode.
func Load(dataDir string, coldKey ed25519.PublicKey) (*State, error) {
	dir := filepath.Join(dataDir, pauseDirname)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	s := &State{
		dir:     dir,
		coldKey: coldKey,
	}

	// Read last_sequence_number. Missing is equivalent to 0 (no prior
	// signal accepted).
	seq, err := readLastSequence(dir)
	if err != nil {
		return nil, fmt.Errorf("read last_sequence_number: %w", err)
	}
	s.lastSeq = seq

	// Read current.json if present. Re-verify.
	cur, err := readCurrent(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read current pause: %w", err)
	}
	if cur != nil {
		// Re-verify on load. Missing cold key or failed verification
		// means we don't trust this file; set aside.
		if coldKey == nil || !verifyEnvelope(coldKey, cur.Envelope) {
			if mvErr := quarantine(dir, currentFilename); mvErr != nil {
				return nil, fmt.Errorf("quarantine invalid current pause: %w", mvErr)
			}
		} else {
			s.active = cur
		}
	}
	return s, nil
}

// Apply validates an inbound pause envelope and, on success, persists it
// as the active pause and advances last_sequence_number. Returns a typed
// error for each failure mode so the HTTP handler can map status codes
// precisely.
//
// Validation order matches design §4.4:
//  1. cold key is configured (else ErrNotConfigured)
//  2. envelope has non-empty payload + signature (else ErrInvalidEnvelope)
//  3. signature decodes to 64 bytes (else ErrInvalidSignatureFormat)
//  4. Ed25519 verify over payload bytes (else ErrInvalidSignature)
//  5. payload JSON parses (else ErrInvalidPayload)
//  6. type, version, scope match constants (else ErrWrongType/Version/Scope)
//  7. expires_at parses and lies in the future (else ErrMalformedTimestamp/ErrExpired)
//  8. sequence_number > lastSeq (else ErrSequenceNotMonotonic)
//  9. persist to disk (atomic rename)
//
// Crucially: steps 1-8 mutate nothing. Only step 9 touches disk or
// in-memory state. This matches the transactional discipline used
// elsewhere in the provider (api/upload.go, api/delete.go).
func (s *State) Apply(env Envelope, now time.Time) (*StoredPause, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.coldKey == nil {
		return nil, ErrNotConfigured
	}
	if env.Payload == "" || env.Signature == "" {
		return nil, ErrInvalidEnvelope
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignatureFormat, err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: wrong length %d, want %d",
			ErrInvalidSignatureFormat, len(sigBytes), ed25519.SignatureSize)
	}
	if !ed25519.Verify(s.coldKey, []byte(env.Payload), sigBytes) {
		return nil, ErrInvalidSignature
	}

	var sig Signal
	if err := json.Unmarshal([]byte(env.Payload), &sig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if sig.Type != SignalType {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrWrongType, sig.Type, SignalType)
	}
	if sig.Version != SignalVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrWrongVersion, sig.Version, SignalVersion)
	}
	if sig.Scope != SignalScope {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrWrongScope, sig.Scope, SignalScope)
	}

	expiresAt, err := parseRFC3339(sig.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("%w: expires_at: %v", ErrMalformedTimestamp, err)
	}
	if !expiresAt.After(now) {
		return nil, ErrExpired
	}
	// issued_at is informational; we parse for validity but don't gate
	// on it (a signal issued earlier and delivered late is still
	// actionable, subject to the sequence-number and expires_at checks).
	if _, err := parseRFC3339(sig.IssuedAt); err != nil {
		return nil, fmt.Errorf("%w: issued_at: %v", ErrMalformedTimestamp, err)
	}

	if sig.SequenceNumber <= s.lastSeq {
		return nil, fmt.Errorf("%w: got %d, last-seen %d",
			ErrSequenceNotMonotonic, sig.SequenceNumber, s.lastSeq)
	}

	stored := &StoredPause{Envelope: env, Signal: sig}

	// Persist. Write current.json first, then advance
	// last_sequence_number. If we crash between the two, restart re-
	// verifies current.json (good) and reads last_sequence_number (stale
	// but conservative: a future signal with the same sequence would be
	// rejected, which is the safe direction). The only way to end up
	// with last_sequence_number ahead of current.json is a manual edit.
	if err := writeCurrent(s.dir, stored); err != nil {
		return nil, fmt.Errorf("write current pause: %w", err)
	}
	if err := writeLastSequence(s.dir, sig.SequenceNumber); err != nil {
		return nil, fmt.Errorf("write last_sequence_number: %w", err)
	}

	s.active = stored
	s.lastSeq = sig.SequenceNumber
	return stored, nil
}

// IsPaused reports whether a pause is currently in effect at `now`.
// This is the gate that all coverage-driven prune-decision code paths
// must check before acting. Returns false when no pause is active and
// when the active pause has auto-expired. Safe for concurrent use.
func (s *State) IsPaused(now time.Time) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return false
	}
	expiresAt, err := parseRFC3339(s.active.Signal.ExpiresAt)
	if err != nil {
		// Malformed on disk — fail closed (treat as paused). This is
		// conservative: a malformed pause state errs on the side of
		// retention, which is the correct bias per design.
		return true
	}
	return expiresAt.After(now)
}

// Current returns a snapshot of the active pause, or nil if none is
// active (including when the active pause has auto-expired). Safe for
// concurrent use.
func (s *State) Current(now time.Time) *StoredPause {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return nil
	}
	expiresAt, err := parseRFC3339(s.active.Signal.ExpiresAt)
	if err != nil {
		// Malformed on disk — surface it so operators can see the value
		// that's keeping the provider in retain-only mode.
		cp := *s.active
		return &cp
	}
	if !expiresAt.After(now) {
		return nil
	}
	cp := *s.active
	return &cp
}

// LastSequence returns the highest sequence number ever accepted. Useful
// for operator tooling ("what number should I use for the next signal?").
func (s *State) LastSequence() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSeq
}

// ColdKeyConfigured reports whether the state was initialised with a
// non-nil cold key. Used by the HTTP layer to distinguish "unconfigured"
// from "configured but signal rejected."
func (s *State) ColdKeyConfigured() bool {
	return s.coldKey != nil
}

// ----- cold-key parsing --------------------------------------------------

// ParseColdKey decodes an "obk_sig_<43 b64url>" string into a raw
// Ed25519 public key. Empty input returns (nil, nil) — the caller can
// treat a nil return as "no cold key configured."
//
// Mirrors api/delete.go:decodeEd25519Fingerprint. Kept here to avoid
// adding a cross-package dependency from pausectl to api.
func ParseColdKey(s string) (ed25519.PublicKey, error) {
	if s == "" {
		return nil, nil
	}
	if !strings.HasPrefix(s, ColdKeyPrefix) {
		return nil, fmt.Errorf("cold key missing %s prefix", ColdKeyPrefix)
	}
	payload := strings.TrimPrefix(s, ColdKeyPrefix)
	if len(payload) != 43 {
		return nil, fmt.Errorf("cold key encoded length %d, want 43", len(payload))
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("cold key base64url decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("cold key decoded %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ----- internal helpers --------------------------------------------------

func verifyEnvelope(pub ed25519.PublicKey, env Envelope) bool {
	sigBytes, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(env.Payload), sigBytes)
}

func parseRFC3339(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func readCurrent(dir string) (*StoredPause, error) {
	data, err := os.ReadFile(filepath.Join(dir, currentFilename))
	if err != nil {
		return nil, err
	}
	var sp StoredPause
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, fmt.Errorf("parse current.json: %w", err)
	}
	return &sp, nil
}

func writeCurrent(dir string, sp *StoredPause) error {
	data, err := json.MarshalIndent(sp, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, currentFilename), data)
}

func readLastSequence(dir string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(dir, lastSeqFilename))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", lastSeqFilename, err)
	}
	return v, nil
}

func writeLastSequence(dir string, seq int64) error {
	return atomicWrite(filepath.Join(dir, lastSeqFilename),
		[]byte(strconv.FormatInt(seq, 10)+"\n"))
}

// quarantine renames a file aside so a human operator can inspect it
// without blocking provider startup. Used on Load when a persisted
// current.json fails signature verification (e.g., after a cold-key
// rotation or disk corruption).
func quarantine(dir, name string) error {
	src := filepath.Join(dir, name)
	dst := filepath.Join(dir, name+".rejected-"+time.Now().UTC().Format("20060102T150405Z"))
	return os.Rename(src, dst)
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
