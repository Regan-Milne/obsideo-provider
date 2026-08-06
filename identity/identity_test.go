package identity

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreate_GeneratesThenPersists(t *testing.T) {
	dir := t.TempDir()

	id1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	if len(id1.PublicKey()) != ed25519.PublicKeySize {
		t.Fatalf("bad public key size: %d", len(id1.PublicKey()))
	}

	// Key file exists with 0600 perms (perm check is meaningful on Unix).
	path := filepath.Join(dir, KeyFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("key file not written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 && perm != 0o666 /*windows*/ {
		t.Fatalf("unexpected key file perms: %o", perm)
	}

	// Second load returns the SAME identity — never regenerates.
	id2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if id1.PublicKeyHex() != id2.PublicKeyHex() {
		t.Fatalf("identity changed across reload: %s != %s", id1.PublicKeyHex(), id2.PublicKeyHex())
	}
}

func TestLoadOrCreate_NeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	id1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, KeyFileName))

	// Repeated loads must not rewrite the file.
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatalf("reload: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, KeyFileName))
	if string(before) != string(after) {
		t.Fatal("key file was rewritten on reload")
	}
	_ = id1
}

func TestLoadOrCreate_MalformedKeyIsHardError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeyFileName), []byte("not a pem key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("expected hard error on malformed key, got nil (silent regenerate would invalidate all prior proofs)")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("challenge payload")
	sig := id.Sign(msg)
	if !ed25519.Verify(id.PublicKey(), msg, sig) {
		t.Fatal("signature did not verify against own public key")
	}
	// A different message must not verify.
	if ed25519.Verify(id.PublicKey(), []byte("other"), sig) {
		t.Fatal("signature verified against wrong message")
	}
}

func TestKeyID_StableAndDerivedFromPubkey(t *testing.T) {
	id, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := id.KeyID(); got != id.PublicKeyHex()[:16] {
		t.Fatalf("KeyID %q not the pubkey prefix %q", got, id.PublicKeyHex()[:16])
	}
}
