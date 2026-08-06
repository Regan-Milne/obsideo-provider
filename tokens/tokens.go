package tokens

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Claims matches the coordinator's token payload.
//
// OwnerPubkey and OwnerSigPubkey are v2.1 additions carried on upload
// tokens for retention-authority Phase 1. See
// docs/retention_authority_design.md §6.1. Both are `omitempty`: legacy
// accounts (pre-Phase-1) produce tokens that omit these fields; the
// upload handler treats that as "skip ownership file write," which is
// the documented mixed-state rule from design §9.2.
type Claims struct {
	Type           string `json:"type"`        // "upload" | "download"
	MerkleRoot     string `json:"merkle_root"` // hex
	ProviderID     string `json:"provider_id"`
	AccountID      string `json:"account_id"`
	OwnerPubkey    string `json:"owner_pubkey,omitempty"`
	OwnerSigPubkey string `json:"owner_sig_pubkey,omitempty"`
	// Contracted records account.IsContracted(acct, now) at coord
	// token-mint time. Populated on upload tokens; absent on download
	// tokens. The upload handler consumes this to enforce the operator's
	// `accept_uncontracted_data` config gate at the upload boundary —
	// same canonical predicate the GC sweeper uses, just earlier in the
	// data lifecycle. Single source of truth for "is the provider being
	// paid to keep this right now?".
	Contracted bool  `json:"contracted,omitempty"`
	IssuedAt   int64 `json:"iat"`
	ExpiresAt  int64 `json:"exp"`
}

// Verifier holds a list of Ed25519 public keys that are authorized to
// sign coord-issued tokens. A token verifies if its signature checks
// against ANY key in the list.
//
// The single-key case (legacy: just the central Coord's pubkey) is
// represented as a list of one. The multi-key case (DC architecture
// Phase 1+: central Coord pubkey + zero-or-more registered DC pubkeys)
// extends the list. See [[dc_transition_plan]] §"Architectural decisions
// locked" decision 1 for the authority split this enables.
//
// AddKey is safe for concurrent use; the directory-fetch goroutine
// calls it when it observes a new authorized signer in a fresh
// snapshot.
type Verifier struct {
	mu   sync.RWMutex
	pubs []ed25519.PublicKey
}

// NewVerifierForTesting constructs a Verifier from an in-memory Ed25519
// public key. Test-only; production callers use NewVerifier which enforces
// the PEM-on-disk load path.
func NewVerifierForTesting(pub ed25519.PublicKey) *Verifier {
	return &Verifier{pubs: []ed25519.PublicKey{pub}}
}

// NewVerifierMulti constructs a Verifier from a list of Ed25519 public
// keys. Test-only seed for the multi-authority path; production callers
// build up the list via NewVerifier (loads central Coord pubkey from
// PEM) followed by AddKey calls (DC pubkeys from the signed directory).
func NewVerifierMulti(pubs []ed25519.PublicKey) *Verifier {
	out := make([]ed25519.PublicKey, len(pubs))
	copy(out, pubs)
	return &Verifier{pubs: out}
}

// NewVerifier loads the coordinator's Ed25519 public key from a PEM file
// and seeds the Verifier with that single key. Additional authorized
// signers (DCs) are added via AddKey when the provider observes them in
// a freshly-fetched signed directory.
//
// The PEM block type must be "PUBLIC KEY" with the raw 32-byte key as
// the body. Format unchanged from the single-key era for backwards
// compatibility with existing deployments — every legacy provider on
// disk has a PEM file pointing at the central Coord's pubkey.
func NewVerifier(pubKeyPath string) (*Verifier, error) {
	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", pubKeyPath, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", pubKeyPath)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key size %d (want %d)", len(block.Bytes), ed25519.PublicKeySize)
	}
	return &Verifier{pubs: []ed25519.PublicKey{ed25519.PublicKey(block.Bytes)}}, nil
}

// AddKey appends a public key to the authorized-signers list if it is
// not already present. Safe to call concurrently with Verify. Returns
// true when the key was added, false when it was already known.
//
// The directory-fetch loop calls this on each refresh for any signer
// that wasn't in the previous snapshot. Idempotent so repeated refreshes
// don't grow the list unbounded.
func (v *Verifier) AddKey(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, existing := range v.pubs {
		if pub.Equal(existing) {
			return false
		}
	}
	dup := make(ed25519.PublicKey, len(pub))
	copy(dup, pub)
	v.pubs = append(v.pubs, dup)
	return true
}

// HasKey reports whether the given public key is in the authorized
// signers list. Used by the directory-fetch loop to decide whether
// AddKey would be a no-op without taking the write lock first.
func (v *Verifier) HasKey(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	for _, existing := range v.pubs {
		if pub.Equal(existing) {
			return true
		}
	}
	return false
}

// KeyCount returns the number of authorized public keys currently in
// the verifier. Useful for tests and operator-side observability (e.g.
// "this provider trusts N coord/DC signers"); not on the hot path.
func (v *Verifier) KeyCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.pubs)
}

// SeedKey returns a copy of the first authorized public key — the one
// the Verifier was constructed with via NewVerifier (or the first
// entry passed to NewVerifierMulti / NewVerifierForTesting). This is
// the central Coord's pubkey loaded from PEM at startup; it is the
// root of trust used by the directory-fetch loop to verify directory
// signatures (the coord-issued envelope that publishes additional DC
// pubkeys). Returns nil if the Verifier was constructed empty.
//
// Caller assumption: SeedKey is read once at startup and treated as
// stable; AddKey appends to the trust list but never reorders it, so
// the index-0 entry remains the constructor key for the lifetime of
// the process. If a future refactor allows reordering or removing the
// seed, this method's contract changes and the directory-fetch loop
// needs to be updated to track the seed separately.
func (v *Verifier) SeedKey() ed25519.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.pubs) == 0 {
		return nil
	}
	out := make(ed25519.PublicKey, len(v.pubs[0]))
	copy(out, v.pubs[0])
	return out
}

// Verify parses and validates a coordinator-issued token.
// Format: base64url(claims_json).base64url(ed25519_sig)
//
// The signature is checked against each public key in the authorized-
// signers list; the first match wins. Token rejected only after all
// keys fail. Cost is O(N) ed25519 verifies in the worst case (small N
// in practice — central Coord + a few DCs at most), and the common
// case is N=1 (legacy single-coord deployments) where it's identical
// to the pre-multi-authority code path.
func (v *Verifier) Verify(token string) (*Claims, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("malformed token: expected 2 dot-separated parts")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	v.mu.RLock()
	pubs := v.pubs
	v.mu.RUnlock()

	verified := false
	for _, pub := range pubs {
		if ed25519.Verify(pub, claimsBytes, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("invalid token signature")
	}

	var c Claims
	if err := json.Unmarshal(claimsBytes, &c); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if time.Now().Unix() > c.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	return &c, nil
}
