package store

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Tests for retention-authority Phase 1 ownership persistence (D1).
// Spec reference: docs/retention_authority_design.md §9.1 + §9.2.

func newTempStore(t *testing.T) *Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "provider-ownership-test-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s, err := New(dir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	return s
}

func validOwnership() Ownership {
	return Ownership{
		OwnerPubkey:    "obk_pub_" + strings.Repeat("A", 43),
		OwnerSigPubkey: "obk_sig_" + strings.Repeat("B", 43),
		ReceivedAt:     time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
	}
}

func TestPutOwnership_HappyPath(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("a", 64)
	if err := s.PutOwnership(merkle, validOwnership()); err != nil {
		t.Fatalf("PutOwnership: %v", err)
	}
	if !s.HasOwnership(merkle) {
		t.Errorf("HasOwnership returned false after PutOwnership")
	}
	got, err := s.GetOwnership(merkle)
	if err != nil {
		t.Fatalf("GetOwnership: %v", err)
	}
	want := validOwnership()
	if got.OwnerPubkey != want.OwnerPubkey {
		t.Errorf("OwnerPubkey = %q, want %q", got.OwnerPubkey, want.OwnerPubkey)
	}
	if got.OwnerSigPubkey != want.OwnerSigPubkey {
		t.Errorf("OwnerSigPubkey = %q, want %q", got.OwnerSigPubkey, want.OwnerSigPubkey)
	}
	if !got.ReceivedAt.Equal(want.ReceivedAt) {
		t.Errorf("ReceivedAt = %v, want %v", got.ReceivedAt, want.ReceivedAt)
	}
}

func TestPutOwnership_RejectsEmptyOwnerPubkey(t *testing.T) {
	s := newTempStore(t)
	bad := validOwnership()
	bad.OwnerPubkey = ""
	err := s.PutOwnership("abc123", bad)
	if err == nil {
		t.Fatal("expected error for empty OwnerPubkey")
	}
}

func TestPutOwnership_RejectsEmptyOwnerSigPubkey(t *testing.T) {
	s := newTempStore(t)
	bad := validOwnership()
	bad.OwnerSigPubkey = ""
	err := s.PutOwnership("abc123", bad)
	if err == nil {
		t.Fatal("expected error for empty OwnerSigPubkey")
	}
}

func TestPutOwnership_WriteOnce_SecondCallReturnsErrOwnershipExists(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("c", 64)
	if err := s.PutOwnership(merkle, validOwnership()); err != nil {
		t.Fatalf("first PutOwnership: %v", err)
	}
	// Second attempt, even with identical content, must be rejected.
	err := s.PutOwnership(merkle, validOwnership())
	if !errors.Is(err, ErrOwnershipExists) {
		t.Errorf("second PutOwnership: want ErrOwnershipExists, got %v", err)
	}
}

func TestPutOwnership_FileModeIs0o444(t *testing.T) {
	// The write-once-immutable invariant (design §9.1) requires mode 0o444
	// so accidental mutation hits EPERM. Check the stat.
	// Skip on Windows where chmod semantics differ; the test stays
	// meaningful on POSIX CI and prod.
	if runtime.GOOS == "windows" {
		t.Skip("file mode 0o444 has different semantics on Windows")
	}
	s := newTempStore(t)
	merkle := strings.Repeat("d", 64)
	if err := s.PutOwnership(merkle, validOwnership()); err != nil {
		t.Fatalf("PutOwnership: %v", err)
	}
	info, err := os.Stat(s.ownPath(merkle))
	if err != nil {
		t.Fatal(err)
	}
	got := info.Mode() & 0o777
	if got != 0o444 {
		t.Errorf("ownership file mode = %o, want 0o444", got)
	}
}

func TestGetOwnership_ReturnsErrNotFoundWhenAbsent(t *testing.T) {
	s := newTempStore(t)
	_, err := s.GetOwnership("notpresent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetOwnership missing: want ErrNotFound, got %v", err)
	}
}

func TestHasOwnership_FalseWhenAbsent(t *testing.T) {
	s := newTempStore(t)
	if s.HasOwnership("notpresent") {
		t.Errorf("HasOwnership returned true for non-existent merkle root")
	}
}

func TestDelete_RemovesOwnershipFile(t *testing.T) {
	s := newTempStore(t)
	merkle := strings.Repeat("e", 64)
	if err := s.PutOwnership(merkle, validOwnership()); err != nil {
		t.Fatalf("PutOwnership: %v", err)
	}
	// Also write a dummy object/index so Delete has a full set to clean.
	if err := s.Put(merkle, []byte("placeholder"), DefaultChunkSize); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(merkle); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if s.HasOwnership(merkle) {
		t.Errorf("ownership file persists after Delete")
	}
	if _, err := s.GetOwnership(merkle); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetOwnership after Delete: want ErrNotFound, got %v", err)
	}
}

func TestOwnership_JSONFieldNamesMatchSpec(t *testing.T) {
	// Spec docs/retention_authority_design.md §9 mandates the JSON field
	// names owner_pubkey, owner_sig_pubkey, received_at. Verify by reading
	// the raw file contents rather than round-tripping through Go structs
	// (which would mask a tag mistake).
	s := newTempStore(t)
	merkle := strings.Repeat("f", 64)
	if err := s.PutOwnership(merkle, validOwnership()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.ownPath(merkle))
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	for _, key := range []string{`"owner_pubkey"`, `"owner_sig_pubkey"`, `"received_at"`} {
		if !strings.Contains(content, key) {
			t.Errorf("ownership file missing JSON field %s; got: %s", key, content)
		}
	}
}
