package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// mintToken produces the same wire format the coordinator emits:
// base64url(claims_json).base64url(ed25519_sig).
func mintToken(t *testing.T, priv ed25519.PrivateKey, claims Claims) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sig := ed25519.Sign(priv, body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func validClaims() Claims {
	return Claims{
		Type:       "upload",
		MerkleRoot: strings.Repeat("ab", 32),
		ProviderID: "p1",
		AccountID:  "acct-1",
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}
}

func TestVerifier_SingleKey_LegacyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifierForTesting(pub)
	if v.KeyCount() != 1 {
		t.Errorf("KeyCount = %d, want 1 (single-key legacy seed)", v.KeyCount())
	}

	tok := mintToken(t, priv, validClaims())
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify failed on token signed by trusted key: %v", err)
	}
	if got.MerkleRoot != strings.Repeat("ab", 32) {
		t.Errorf("MerkleRoot round-trip wrong: %s", got.MerkleRoot)
	}
}

func TestVerifier_SingleKey_RejectsUnknownSigner(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierForTesting(pub)

	tok := mintToken(t, otherPriv, validClaims())
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted token signed by untrusted key")
	}
}

// TestVerifier_MultiKey_AcceptsAnyTrustedSigner pins the Phase 1 multi-
// authority promise: a token signed by ANY key in the authorized-signers
// list verifies. Pre-multi-authority, only the single coord key worked.
func TestVerifier_MultiKey_AcceptsAnyTrustedSigner(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierMulti([]ed25519.PublicKey{pubA, pubB})
	if v.KeyCount() != 2 {
		t.Errorf("KeyCount = %d, want 2", v.KeyCount())
	}

	tokA := mintToken(t, privA, validClaims())
	if _, err := v.Verify(tokA); err != nil {
		t.Errorf("Verify(tokA): %v", err)
	}
	tokB := mintToken(t, privB, validClaims())
	if _, err := v.Verify(tokB); err != nil {
		t.Errorf("Verify(tokB): %v", err)
	}
}

func TestVerifier_MultiKey_RejectsUntrustedSigner(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierMulti([]ed25519.PublicKey{pubA, pubB})

	tok := mintToken(t, otherPriv, validClaims())
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted token from key not in authorized-signers list")
	}
}

func TestVerifier_AddKey_Idempotent(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierMulti(nil)
	if v.KeyCount() != 0 {
		t.Errorf("empty seed: KeyCount = %d, want 0", v.KeyCount())
	}
	if added := v.AddKey(pub); !added {
		t.Error("first AddKey: returned false; want true")
	}
	if v.KeyCount() != 1 {
		t.Errorf("after first AddKey: KeyCount = %d, want 1", v.KeyCount())
	}
	if added := v.AddKey(pub); added {
		t.Error("duplicate AddKey: returned true; want false (no-op)")
	}
	if v.KeyCount() != 1 {
		t.Errorf("after duplicate AddKey: KeyCount = %d, want 1 (no growth)", v.KeyCount())
	}
}

func TestVerifier_AddKey_RejectsWrongSize(t *testing.T) {
	v := NewVerifierMulti(nil)
	if added := v.AddKey([]byte{1, 2, 3}); added {
		t.Error("AddKey with wrong-size key returned true; want false")
	}
	if v.KeyCount() != 0 {
		t.Errorf("KeyCount = %d after rejected AddKey, want 0", v.KeyCount())
	}
}

func TestVerifier_HasKey(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierMulti([]ed25519.PublicKey{pubA})
	if !v.HasKey(pubA) {
		t.Error("HasKey(pubA): false; want true")
	}
	if v.HasKey(pubB) {
		t.Error("HasKey(pubB): true; want false (not yet added)")
	}
	v.AddKey(pubB)
	if !v.HasKey(pubB) {
		t.Error("HasKey(pubB) after AddKey: false; want true")
	}
}

// TestVerifier_AddKey_AfterStartAccepts pins the directory-fetch use
// case: at startup the Verifier seeds with just the central Coord
// pubkey; later, when the provider observes a DC pubkey in a fresh
// signed directory, it calls AddKey and the next token signed by that
// DC verifies cleanly. No restart required.
func TestVerifier_AddKey_AfterStartAccepts(t *testing.T) {
	coordPub, coordPriv, _ := ed25519.GenerateKey(rand.Reader)
	dcPub, dcPriv, _ := ed25519.GenerateKey(rand.Reader)

	v := NewVerifierForTesting(coordPub) // single-key legacy seed

	dcTok := mintToken(t, dcPriv, validClaims())
	if _, err := v.Verify(dcTok); err == nil {
		t.Fatal("Verify accepted DC token before AddKey")
	}

	if added := v.AddKey(dcPub); !added {
		t.Fatal("AddKey returned false on a new key")
	}

	// DC token now verifies.
	if _, err := v.Verify(dcTok); err != nil {
		t.Errorf("DC token verification after AddKey: %v", err)
	}
	// Coord token still verifies.
	coordTok := mintToken(t, coordPriv, validClaims())
	if _, err := v.Verify(coordTok); err != nil {
		t.Errorf("Coord token verification after AddKey: %v", err)
	}
}

// TestVerifier_ConcurrentAddAndVerify exercises the read-write lock —
// AddKey must not race against in-flight Verify calls. The directory-
// fetch loop calls AddKey while request handlers concurrently call
// Verify; ed25519.Verify is fast but not instant, so a coarse-grained
// lock that blocked verifies during AddKey would hurt throughput.
func TestVerifier_ConcurrentAddAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierForTesting(pub)
	tok := mintToken(t, priv, validClaims())

	var wg sync.WaitGroup
	const N = 50
	wg.Add(N * 2)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			if _, err := v.Verify(tok); err != nil {
				t.Errorf("Verify failed under concurrent AddKey: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			newPub, _, _ := ed25519.GenerateKey(rand.Reader)
			v.AddKey(newPub)
		}()
	}
	wg.Wait()

	if v.KeyCount() != N+1 { // 1 seed + N adds
		t.Errorf("after concurrent adds: KeyCount = %d, want %d", v.KeyCount(), N+1)
	}
}

func TestVerifier_RejectsExpiredToken(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierForTesting(pub)
	expired := validClaims()
	expired.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	tok := mintToken(t, priv, expired)
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted expired token")
	}
}

func TestVerifier_RejectsMalformedToken(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	v := NewVerifierForTesting(pub)
	for _, tok := range []string{"", "no-dot", "....."} {
		if _, err := v.Verify(tok); err == nil {
			t.Errorf("Verify accepted malformed token %q", tok)
		}
	}
}
