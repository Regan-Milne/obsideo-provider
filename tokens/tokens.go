package tokens

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
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
	IssuedAt       int64  `json:"iat"`
	ExpiresAt      int64  `json:"exp"`
}

// Verifier holds the coordinator's Ed25519 public key.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifierForTesting constructs a Verifier from an in-memory Ed25519
// public key. Test-only; production callers use NewVerifier which enforces
// the PEM-on-disk load path.
func NewVerifierForTesting(pub ed25519.PublicKey) *Verifier {
	return &Verifier{pub: pub}
}

// NewVerifier loads the coordinator's Ed25519 public key from a PEM file.
// The PEM block type must be "PUBLIC KEY" with the raw 32-byte key as the body.
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
	return &Verifier{pub: ed25519.PublicKey(block.Bytes)}, nil
}

// Verify parses and validates a coordinator-issued token.
// Format: base64url(claims_json).base64url(ed25519_sig)
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

	if !ed25519.Verify(v.pub, claimsBytes, sig) {
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
