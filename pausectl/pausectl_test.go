package pausectl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Tests for the retention-authority circuit breaker (D5). Spec:
// docs/retention_authority_design.md §4.4 and §12 invariant 5.
//
// Invariant checklist that these tests collectively enforce:
//   - signature verification against the configured cold key only (wrong
//     key → ErrInvalidSignature)
//   - sequence-number strict monotonicity (replay / regression rejected)
//   - expires_at must be in the future (past → ErrExpired; there is no
//     "resume" message)
//   - only type="obsideo.pause-signal", version=1, scope="coverage-
//     enforcement" accepted
//   - on-disk state persists sequence number across restarts
//   - a persisted current.json that fails re-verify on Load is
//     quarantined so a bad state does not lock the provider in pause

// pauseTestEnv builds a fresh cold-key pair, a fresh State rooted in a
// temp dir, and returns signing helpers that produce valid envelopes
// for arbitrary signal fields. Tests compose these helpers and mutate
// individual fields to exercise each failure mode without duplicating
// the scaffolding.
type pauseTestEnv struct {
	dir     string
	coldPub ed25519.PublicKey
	coldPri ed25519.PrivateKey
	state   *State
}

func newPauseEnv(t *testing.T) *pauseTestEnv {
	t.Helper()
	pub, pri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	state, err := Load(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	return &pauseTestEnv{dir: dir, coldPub: pub, coldPri: pri, state: state}
}

// signSignal canonicalises the fields as JSON (stdlib Marshal is
// deterministic enough for tests: we control all inputs so there is no
// interop risk with another encoder) and signs. Returns the envelope
// ready for Apply.
func (e *pauseTestEnv) signSignal(t *testing.T, s Signal) Envelope {
	t.Helper()
	payload, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(e.coldPri, payload)
	return Envelope{
		Payload:   string(payload),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func validSignal(seq int64, expiresAt time.Time) Signal {
	return Signal{
		Type:           SignalType,
		Version:        SignalVersion,
		IssuedAt:       time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:      expiresAt.UTC().Format(time.RFC3339),
		Scope:          SignalScope,
		SequenceNumber: seq,
		Reason:         "unit-test",
	}
}

func TestApply_HappyPath(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	stored, err := env.state.Apply(env.signSignal(t, validSignal(1, expiry)), now)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if stored.Signal.SequenceNumber != 1 {
		t.Errorf("sequence: got %d want 1", stored.Signal.SequenceNumber)
	}
	if !env.state.IsPaused(now) {
		t.Error("IsPaused should be true immediately after accepting")
	}
	if env.state.LastSequence() != 1 {
		t.Errorf("LastSequence: got %d want 1", env.state.LastSequence())
	}

	// current.json and last_sequence_number must be on disk.
	if _, err := os.Stat(filepath.Join(env.dir, "pause", "current.json")); err != nil {
		t.Errorf("current.json not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.dir, "pause", "last_sequence_number")); err != nil {
		t.Errorf("last_sequence_number not written: %v", err)
	}
}

func TestApply_Monotonicity(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	if _, err := env.state.Apply(env.signSignal(t, validSignal(5, expiry)), now); err != nil {
		t.Fatalf("first Apply: %v", err)
	}

	// Equal sequence → rejected.
	_, err := env.state.Apply(env.signSignal(t, validSignal(5, expiry)), now)
	if !errors.Is(err, ErrSequenceNotMonotonic) {
		t.Errorf("equal seq: got %v want ErrSequenceNotMonotonic", err)
	}

	// Lower sequence → rejected.
	_, err = env.state.Apply(env.signSignal(t, validSignal(4, expiry)), now)
	if !errors.Is(err, ErrSequenceNotMonotonic) {
		t.Errorf("lower seq: got %v want ErrSequenceNotMonotonic", err)
	}

	// Higher sequence → accepted, advances counter.
	if _, err := env.state.Apply(env.signSignal(t, validSignal(6, expiry)), now); err != nil {
		t.Errorf("higher seq: %v", err)
	}
	if env.state.LastSequence() != 6 {
		t.Errorf("LastSequence after three signals: got %d want 6", env.state.LastSequence())
	}
}

func TestApply_Expired(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()

	// expires_at in the past → ErrExpired.
	_, err := env.state.Apply(env.signSignal(t, validSignal(1, now.Add(-1*time.Minute))), now)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("past expiry: got %v want ErrExpired", err)
	}

	// Equal to now is not "in the future" either.
	_, err = env.state.Apply(env.signSignal(t, validSignal(1, now)), now)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("equal expiry: got %v want ErrExpired", err)
	}
}

func TestApply_WrongSignature(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()

	// Sign with a different key; original envelope's payload stays but
	// signature is now invalid against env.coldPub.
	_, otherPri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(validSignal(1, now.Add(24*time.Hour)))
	wrongSig := ed25519.Sign(otherPri, payload)
	bad := Envelope{
		Payload:   string(payload),
		Signature: base64.RawURLEncoding.EncodeToString(wrongSig),
	}

	_, err = env.state.Apply(bad, now)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("wrong key: got %v want ErrInvalidSignature", err)
	}
}

func TestApply_TamperedPayload(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()

	good := env.signSignal(t, validSignal(1, now.Add(24*time.Hour)))
	// Mutate one byte of the payload without touching the signature.
	tampered := Envelope{
		Payload:   strings.Replace(good.Payload, `"reason":"unit-test"`, `"reason":"TAMPERED"`, 1),
		Signature: good.Signature,
	}
	if tampered.Payload == good.Payload {
		t.Fatal("tamper did not change payload; test is ineffective")
	}

	_, err := env.state.Apply(tampered, now)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("tampered payload: got %v want ErrInvalidSignature", err)
	}
}

func TestApply_MalformedSignatureBase64(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	env2 := env.signSignal(t, validSignal(1, now.Add(24*time.Hour)))
	env2.Signature = "not!valid!base64!"

	_, err := env.state.Apply(env2, now)
	if !errors.Is(err, ErrInvalidSignatureFormat) {
		t.Errorf("bad b64: got %v want ErrInvalidSignatureFormat", err)
	}
}

func TestApply_WrongSignatureLength(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	env2 := env.signSignal(t, validSignal(1, now.Add(24*time.Hour)))
	// Truncate the signature.
	env2.Signature = base64.RawURLEncoding.EncodeToString([]byte("too short"))

	_, err := env.state.Apply(env2, now)
	if !errors.Is(err, ErrInvalidSignatureFormat) {
		t.Errorf("short sig: got %v want ErrInvalidSignatureFormat", err)
	}
}

func TestApply_WrongTypeVersionScope(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	cases := []struct {
		name   string
		mutate func(s *Signal)
		want   error
	}{
		{"wrong type", func(s *Signal) { s.Type = "obsideo.other" }, ErrWrongType},
		{"wrong version", func(s *Signal) { s.Version = 2 }, ErrWrongVersion},
		{"wrong scope", func(s *Signal) { s.Scope = "all" }, ErrWrongScope},
	}
	for seq, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSignal(int64(seq+1), expiry)
			tc.mutate(&s)
			_, err := env.state.Apply(env.signSignal(t, s), now)
			if !errors.Is(err, tc.want) {
				t.Errorf("%s: got %v want %v", tc.name, err, tc.want)
			}
		})
	}
}

func TestApply_MalformedTimestamp(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()

	s := validSignal(1, now.Add(24*time.Hour))
	s.ExpiresAt = "not a date"
	_, err := env.state.Apply(env.signSignal(t, s), now)
	if !errors.Is(err, ErrMalformedTimestamp) {
		t.Errorf("bad expires_at: got %v want ErrMalformedTimestamp", err)
	}

	s2 := validSignal(1, now.Add(24*time.Hour))
	s2.IssuedAt = "still not a date"
	_, err = env.state.Apply(env.signSignal(t, s2), now)
	if !errors.Is(err, ErrMalformedTimestamp) {
		t.Errorf("bad issued_at: got %v want ErrMalformedTimestamp", err)
	}
}

func TestApply_EmptyEnvelope(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()

	_, err := env.state.Apply(Envelope{}, now)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("empty: got %v want ErrInvalidEnvelope", err)
	}
	_, err = env.state.Apply(Envelope{Payload: "{}"}, now)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("missing sig: got %v want ErrInvalidEnvelope", err)
	}
}

func TestApply_NoColdKey(t *testing.T) {
	dir := t.TempDir()
	state, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.ColdKeyConfigured() {
		t.Fatal("ColdKeyConfigured should be false with nil key")
	}

	_, err = state.Apply(Envelope{Payload: "x", Signature: "y"}, time.Now().UTC())
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no cold key: got %v want ErrNotConfigured", err)
	}
	if state.IsPaused(time.Now().UTC()) {
		t.Error("IsPaused should be false when no cold key is configured")
	}
}

func TestIsPaused_AutoExpires(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	expiry := now.Add(10 * time.Minute)

	if _, err := env.state.Apply(env.signSignal(t, validSignal(1, expiry)), now); err != nil {
		t.Fatal(err)
	}

	if !env.state.IsPaused(now) {
		t.Error("IsPaused should be true before expiry")
	}
	if !env.state.IsPaused(expiry.Add(-1 * time.Second)) {
		t.Error("IsPaused should still be true 1s before expiry")
	}
	if env.state.IsPaused(expiry) {
		t.Error("IsPaused should be false at exact expiry (not strictly after)")
	}
	if env.state.IsPaused(expiry.Add(1 * time.Second)) {
		t.Error("IsPaused should be false after expiry")
	}

	// Current() respects the same rule.
	if env.state.Current(expiry.Add(1*time.Second)) != nil {
		t.Error("Current should return nil once auto-expired")
	}
}

func TestLoad_PersistsAcrossRestart(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	if _, err := env.state.Apply(env.signSignal(t, validSignal(7, expiry)), now); err != nil {
		t.Fatal(err)
	}

	// Simulate restart: Load again with the same cold key + data dir.
	reloaded, err := Load(env.dir, env.coldPub)
	if err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	if reloaded.LastSequence() != 7 {
		t.Errorf("LastSequence after restart: got %d want 7", reloaded.LastSequence())
	}
	if !reloaded.IsPaused(now) {
		t.Error("IsPaused should be true after restart while pause is still valid")
	}
	if cur := reloaded.Current(now); cur == nil || cur.Signal.SequenceNumber != 7 {
		t.Errorf("Current after restart: %+v", cur)
	}

	// A replay at seq=7 must still be rejected across restarts.
	_, err = reloaded.Apply(env.signSignal(t, validSignal(7, expiry)), now)
	if !errors.Is(err, ErrSequenceNotMonotonic) {
		t.Errorf("replay across restart: got %v want ErrSequenceNotMonotonic", err)
	}
}

func TestLoad_QuarantinesInvalidCurrent(t *testing.T) {
	env := newPauseEnv(t)
	now := time.Now().UTC()
	expiry := now.Add(24 * time.Hour)

	if _, err := env.state.Apply(env.signSignal(t, validSignal(3, expiry)), now); err != nil {
		t.Fatal(err)
	}

	// Rotate the cold key. The persisted current.json now fails verify
	// against the new key; Load should quarantine it rather than lock
	// the provider in pause.
	newPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(env.dir, newPub)
	if err != nil {
		t.Fatalf("Load with rotated key: %v", err)
	}
	if reloaded.IsPaused(now) {
		t.Error("IsPaused should be false after quarantine")
	}
	if reloaded.Current(now) != nil {
		t.Error("Current should be nil after quarantine")
	}

	// current.json should no longer exist; a .rejected-* sibling should.
	if _, err := os.Stat(filepath.Join(env.dir, "pause", "current.json")); !os.IsNotExist(err) {
		t.Errorf("current.json should be gone after quarantine, stat err=%v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(env.dir, "pause"))
	foundQuarantine := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "current.json.rejected-") {
			foundQuarantine = true
			break
		}
	}
	if !foundQuarantine {
		t.Error("no quarantine file found under pause/")
	}

	// Last-sequence is preserved across quarantine so a replay of the
	// old signal (even if re-signed with the old key) cannot sneak in
	// under the new key via sequence-number reuse.
	if reloaded.LastSequence() != 3 {
		t.Errorf("LastSequence after quarantine: got %d want 3", reloaded.LastSequence())
	}
}

func TestLoad_MissingDirCreated(t *testing.T) {
	dir := t.TempDir()
	// Remove the pause subdir if Load created it so we can check it
	// gets recreated — but in practice we're checking that a fresh
	// dataDir with no pause/ subdir at all works cleanly.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	state, err := Load(dir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastSequence() != 0 {
		t.Errorf("fresh: LastSequence should be 0, got %d", state.LastSequence())
	}
	if state.IsPaused(time.Now().UTC()) {
		t.Error("fresh: IsPaused should be false")
	}
	if _, err := os.Stat(filepath.Join(dir, "pause")); err != nil {
		t.Errorf("pause/ dir not created: %v", err)
	}
}

func TestParseColdKey(t *testing.T) {
	if k, err := ParseColdKey(""); err != nil || k != nil {
		t.Errorf("empty: got (%v, %v), want (nil, nil)", k, err)
	}
	if _, err := ParseColdKey("not_prefixed"); err == nil {
		t.Error("missing prefix should error")
	}
	if _, err := ParseColdKey("obk_sig_short"); err == nil {
		t.Error("wrong length should error")
	}
	if _, err := ParseColdKey("obk_sig_" + strings.Repeat("!", 43)); err == nil {
		t.Error("invalid base64 should error")
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	encoded := "obk_sig_" + base64.RawURLEncoding.EncodeToString(pub)
	got, err := ParseColdKey(encoded)
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Errorf("size: got %d want %d", len(got), ed25519.PublicKeySize)
	}
	for i := range pub {
		if got[i] != pub[i] {
			t.Errorf("byte %d: got %x want %x", i, got[i], pub[i])
			break
		}
	}
}
