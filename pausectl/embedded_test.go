package pausectl

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// These tests exercise the build-time-injected cold-key var directly.
// In a real release build, coldKeyPubkey is set via go-link -X at
// compile time. The tests mutate it in-process to verify the parsing
// and empty-default branches, then restore the original via t.Cleanup.
//
// Tests are not t.Parallel(): they all mutate the same package-level
// var, so serial execution (the default) is required.

func TestEmbeddedColdKey_EmptyDefault(t *testing.T) {
	// With no ldflag injection, the var is empty and EmbeddedColdKey
	// returns (nil, nil). This is the "no circuit breaker baked in"
	// path the daemon relies on to 503 pauses without aborting
	// startup.
	orig := coldKeyPubkey
	t.Cleanup(func() { coldKeyPubkey = orig })

	coldKeyPubkey = ""
	got, err := EmbeddedColdKey()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestEmbeddedColdKey_ValidInjection(t *testing.T) {
	orig := coldKeyPubkey
	t.Cleanup(func() { coldKeyPubkey = orig })

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coldKeyPubkey = "obk_sig_" + base64.RawURLEncoding.EncodeToString(pub)

	got, err := EmbeddedColdKey()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != ed25519.PublicKeySize {
		t.Fatalf("got size %d, want %d", len(got), ed25519.PublicKeySize)
	}
	for i := range pub {
		if got[i] != pub[i] {
			t.Errorf("byte %d mismatch", i)
			break
		}
	}
}

func TestEmbeddedColdKey_MalformedFailsHard(t *testing.T) {
	// A typo in the ldflag must surface as a non-nil error so the
	// daemon bootstrap aborts rather than silently running without a
	// circuit breaker. Three representative failure modes:
	orig := coldKeyPubkey
	t.Cleanup(func() { coldKeyPubkey = orig })

	cases := []string{
		"not_prefixed",                      // missing obk_sig_
		"obk_sig_tooshort",                  // wrong length
		"obk_sig_" + string(make([]byte, 43)), // 43 bytes of NUL — invalid b64url chars
	}
	for _, c := range cases {
		coldKeyPubkey = c
		_, err := EmbeddedColdKey()
		if err == nil {
			t.Errorf("%q: err should be non-nil", c)
		}
	}
}
