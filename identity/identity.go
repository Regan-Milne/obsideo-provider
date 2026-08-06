// Package identity gives a provider a persistent Ed25519 signing identity.
//
// Why this exists: before this package, provider-clean had no private key of
// its own. Every ed25519.Sign in the codebase was in a test; all provider
// crypto was verify-only (coord tokens, coord directory snapshots, customer
// delete signatures, cold-key pause envelopes). A challenge response was
// therefore unattributable — a third party handed a passing proof had only
// the coordinator's word that a provider produced it.
//
// This identity lets a provider SIGN its challenge responses, which is the
// foundation of publicly verifiable possession proofs (see the vault note
// note_public_verifiable_proofs / note_signed_proofs_build_plan): a signature
// over the response binds "this provider held this chunk under this challenge"
// to a key a verifier can check, with no trust in the coordinator.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFileName is the on-disk name of the provider's private signing key,
// stored inside the provider data directory.
const KeyFileName = "provider_identity.key"

// Identity is a provider's Ed25519 signing identity. The private key never
// leaves this process; only the public key and signatures are exposed.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// LoadOrCreate loads the provider identity from dataDir/provider_identity.key,
// generating and persisting a fresh keypair (0600) if none exists.
//
// Two deliberate safety properties:
//   - An existing key is NEVER overwritten. Rotation is an explicit, separate
//     operation, not a side effect of a restart — silently minting a new key
//     would change the provider's public key and invalidate every proof it has
//     ever signed.
//   - A malformed existing key is a HARD error, not a silent regenerate, for
//     the same reason: a corrupt file must be noticed by an operator, never
//     papered over with a new identity.
func LoadOrCreate(dataDir string) (*Identity, error) {
	path := filepath.Join(dataDir, KeyFileName)
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		return parseIdentity(data, path)
	case os.IsNotExist(err):
		return generateAndPersist(path)
	default:
		return nil, fmt.Errorf("read provider identity %s: %w", path, err)
	}
}

func parseIdentity(pemBytes []byte, path string) (*Identity, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("provider identity %s: no PEM block found", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("provider identity %s: parse PKCS8: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("provider identity %s: not an Ed25519 key (got %T)", path, key)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("provider identity %s: cannot derive public key", path)
	}
	return &Identity{priv: priv, pub: pub}, nil
}

func generateAndPersist(path string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate provider identity: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal provider identity: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	// O_EXCL so a racing second process cannot clobber a key the first just
	// wrote; 0600 so the private key is never group/world-readable. On a
	// Linux DC box these perms are enforced; on Windows dev they are a no-op
	// but harmless.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create provider identity %s: %w", path, err)
	}
	if _, werr := f.Write(pemBytes); werr != nil {
		f.Close()
		return nil, fmt.Errorf("write provider identity %s: %w", path, werr)
	}
	if cerr := f.Close(); cerr != nil {
		return nil, fmt.Errorf("close provider identity %s: %w", path, cerr)
	}
	return &Identity{priv: priv, pub: pub}, nil
}

// PublicKeyHex returns the hex-encoded Ed25519 public key. This is the exact
// form the coordinator stores in the provider record's public_key field, so a
// provider can report it in its heartbeat and the coord can persist it verbatim.
func (i *Identity) PublicKeyHex() string {
	return hex.EncodeToString(i.pub)
}

// PublicKey returns the raw Ed25519 public key.
func (i *Identity) PublicKey() ed25519.PublicKey {
	return i.pub
}

// KeyID is a short, stable tag for the signing key (first 16 hex chars of the
// public key). Signed responses carry it so a verifier can select the correct
// key across a future rotation without shipping the whole pubkey each time.
func (i *Identity) KeyID() string {
	return hex.EncodeToString(i.pub)[:16]
}

// Sign returns the Ed25519 signature over payload.
func (i *Identity) Sign(payload []byte) []byte {
	return ed25519.Sign(i.priv, payload)
}
