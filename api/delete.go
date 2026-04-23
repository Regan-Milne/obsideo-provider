package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/Regan-Milne/obsideo-provider/store"
)

// User-signed delete handler per docs/retention_authority_design.md §6.3.
//
// Request body matches the SDK's SignedDeleteCommand shape (sdk/src/crypto/sign.ts):
//
//   { "payload": "<canonical JSON string>", "signature": "<base64url 64-byte ed25519 sig>" }
//
// The `payload` is the exact byte-sequence that was signed; the provider
// verifies the signature against `payload` verbatim and only then parses
// the JSON to extract {account_id, merkle_root, issued_at, nonce}. No
// re-canonicalization on verify — closes a class of encoder-mismatch bugs.
//
// Invariant (design §12, item 2): signature verification happens BEFORE any
// chunks are touched. Absence of an ownership file is an automatic reject
// with no legacy fallback.

// deleteCommandDriftWindow is the maximum clock skew between the signer's
// clock and the provider's clock that the provider will tolerate. Design
// §6.3 says "checks `issued_at` is within acceptable drift window"; 5
// minutes each direction is the industry default for signed-command APIs.
const deleteCommandDriftWindow = 5 * time.Minute

// deleteCommandNonceTTL is how long the provider remembers a nonce as
// already-seen. Twice the drift window plus headroom so a reused nonce
// cannot slip in after falling out of cache but still within the
// accept-window for fresh issued_at.
const deleteCommandNonceTTL = 15 * time.Minute

// signedDeleteCommand is the wire shape. Matches sdk/src/crypto/sign.ts.
type signedDeleteCommand struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// deleteCommandPayload is the canonical-JSON-decoded payload per
// docs/retention_authority_design.md §6.3.
type deleteCommandPayload struct {
	AccountID  string `json:"account_id"`
	MerkleRoot string `json:"merkle_root"`
	IssuedAt   string `json:"issued_at"`
	Nonce      string `json:"nonce"`
}

// handleDeleteSigned implements POST /delete/{merkle}. Open to the public
// (no coord-issued auth token required) — authorization is via the
// customer's Ed25519 signature over the canonical command payload.
//
// Ordering of checks is load-bearing:
//   1. Ownership file present. Absence → 404. No legacy fallback.
//   2. Request body shape valid (payload and signature strings present).
//   3. Signature byte-decodes to 64 bytes.
//   4. Ed25519 verify over payload bytes. Fails → 401.
//   5. Payload parses as canonical delete command with all four fields.
//   6. URL `{merkle}` matches `payload.merkle_root`. Mismatch → 400.
//   7. issued_at within drift window. Outside → 401.
//   8. Nonce not in replay cache. Replay → 401.
//   9. Delete the chunks (store.Delete).
//
// Side effect on success: the object file, index, coverage, AND ownership
// records are all removed. The ownership file going away is load-bearing
// for the write-once invariant (§9.1 invariant 4): a future upload of
// the same merkle by the same user will recreate it with fresh
// `received_at`. Design §6.3 treats the deletion as physical removal.
func (s *Server) handleDeleteSigned(w http.ResponseWriter, r *http.Request) {
	merkle := chi.URLParam(r, "merkle")

	// Step 1: ownership file must exist. Legacy data (no ownership
	// written) and pre-Phase-1 uploads auto-reject.
	own, err := s.store.GetOwnership(merkle)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound,
			"no ownership record for this merkle; signed delete is not available (pre-Phase-1 data or not yet uploaded)")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read ownership: "+err.Error())
		return
	}

	// Step 2: decode body.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var cmd signedDeleteCommand
	if err := json.Unmarshal(body, &cmd); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}
	if cmd.Payload == "" || cmd.Signature == "" {
		writeError(w, http.StatusBadRequest, "payload and signature are required")
		return
	}

	// Step 3: signature byte-decode. Must be exactly 64 bytes.
	sigBytes, err := base64.RawURLEncoding.DecodeString(cmd.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature is not valid base64url: "+err.Error())
		return
	}
	if len(sigBytes) != ed25519.SignatureSize {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("signature must be %d bytes (got %d)", ed25519.SignatureSize, len(sigBytes)))
		return
	}

	// Step 4: decode the stored Ed25519 public key from its obk_sig_ form.
	pubBytes, err := decodeEd25519Fingerprint(own.OwnerSigPubkey)
	if err != nil {
		// Ownership file's pubkey is malformed — shouldn't happen
		// because the upload path validated it before writing. Treat
		// as a server-side bug; 500.
		writeError(w, http.StatusInternalServerError, "decode stored signing key: "+err.Error())
		return
	}

	// Step 5: verify signature against payload bytes verbatim. A valid
	// signature over a mangled payload fails here, as does a tampered
	// signature over a valid payload.
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(cmd.Payload), sigBytes) {
		writeError(w, http.StatusUnauthorized, "signature does not verify against stored owner_sig_pubkey")
		return
	}

	// Step 6: parse the now-verified payload.
	var pl deleteCommandPayload
	if err := json.Unmarshal([]byte(cmd.Payload), &pl); err != nil {
		writeError(w, http.StatusBadRequest, "payload is not valid JSON: "+err.Error())
		return
	}
	if pl.AccountID == "" || pl.MerkleRoot == "" || pl.IssuedAt == "" || pl.Nonce == "" {
		writeError(w, http.StatusBadRequest, "payload missing required field")
		return
	}

	// Step 7: URL merkle must match the signed payload's merkle. A valid
	// signature over a payload referring to a different merkle is
	// someone replaying a command at the wrong URL.
	if pl.MerkleRoot != merkle {
		writeError(w, http.StatusBadRequest,
			"payload.merkle_root does not match URL merkle")
		return
	}

	// Step 8: drift window. issued_at must be within ±deleteCommandDriftWindow
	// of server time.
	issuedAt, err := time.Parse(time.RFC3339Nano, pl.IssuedAt)
	if err != nil {
		// Try RFC3339 without sub-second precision.
		issuedAt, err = time.Parse(time.RFC3339, pl.IssuedAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "payload.issued_at is not RFC3339")
			return
		}
	}
	now := time.Now().UTC()
	delta := now.Sub(issuedAt)
	if delta < -deleteCommandDriftWindow || delta > deleteCommandDriftWindow {
		writeError(w, http.StatusUnauthorized,
			fmt.Sprintf("issued_at outside acceptable drift window (%s); refusing", delta))
		return
	}

	// Step 9: nonce replay check. Store-wide cache keyed by
	// (pubkey, nonce). See noncecache.go.
	if seen := s.nonces.Check(own.OwnerSigPubkey, pl.Nonce, now); seen {
		writeError(w, http.StatusUnauthorized, "nonce already used; replay rejected")
		return
	}

	// Step 10: perform the delete. store.Delete removes the object file,
	// index, coverage record, and ownership file (we chmod 0o444 off
	// first for POSIX/Windows portability — see store.Delete).
	if err := s.store.Delete(merkle); err != nil {
		writeError(w, http.StatusInternalServerError, "delete: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":      "deleted",
		"merkle_root": merkle,
	})
}

// decodeEd25519Fingerprint parses an "obk_sig_<43 b64url>" string to the
// raw 32-byte Ed25519 public key. Mirrors the coord's
// parseCustomerSigningPublicKey structural check; no curve validation
// (Go stdlib doesn't expose one, and Verify will fail on invalid points).
func decodeEd25519Fingerprint(s string) ([]byte, error) {
	const prefix = "obk_sig_"
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("missing %s prefix", prefix)
	}
	payload := strings.TrimPrefix(s, prefix)
	if len(payload) != 43 {
		return nil, fmt.Errorf("encoded length %d, want 43", len(payload))
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decoded %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return raw, nil
}

// ----- Nonce replay cache ------------------------------------------------

// nonceCache prevents replay of signed delete commands. Keyed by
// (owner_sig_pubkey + nonce) so two different users can legitimately
// produce the same nonce without collision. Entries live for
// deleteCommandNonceTTL and are cleaned up opportunistically on insert.
type nonceCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // key → expiry
	ttl     time.Duration
}

func newNonceCache(ttl time.Duration) *nonceCache {
	return &nonceCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// Check reports whether the (pubkey, nonce) pair has been seen already.
// Returns true if a REPLAY was detected (nonce already in cache and not
// yet expired). Returns false (and records the nonce) on first use.
func (c *nonceCache) Check(pubkey, nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Opportunistic cleanup: sweep expired entries whenever the map is
	// big enough to care. Cheaper than a goroutine ticker for the
	// sub-hundred-entries scale Phase 1 operates at.
	if len(c.entries) > 256 {
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
	}

	key := pubkey + "\x00" + nonce // \x00 separator: pubkey can't contain it
	if exp, seen := c.entries[key]; seen {
		if now.Before(exp) {
			return true
		}
		// Expired entry — fall through and record fresh.
	}
	c.entries[key] = now.Add(c.ttl)
	return false
}
