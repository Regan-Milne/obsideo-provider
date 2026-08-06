// Package dirfetch fetches the central Coord's signed provider directory
// on a periodic interval, verifies its signature against the central
// Coord's pubkey loaded at startup, and adds any newly-observed
// authorized signers to the provider's tokens.Verifier.
//
// This is the Phase 1 multi-authority adoption path on the provider
// side: when central Coord registers a new DC's pubkey (Phase 3), the
// next directory refresh will surface it here and the provider's
// Verifier will start accepting tokens signed by that DC.
//
// Trust model: the central Coord's pubkey is the ROOT OF TRUST, loaded
// from coordinator_pub.pem at provider startup. Every directory the
// refresher consumes must verify against that root. A signature mismatch
// causes the refresh to log an error and skip the update entirely —
// fail-closed against bad signed state, never replace the in-memory
// trust list with unverified data.
//
// Backwards compatibility: a directory that lacks the authorized_signers
// field (legacy format) is treated as empty — no new keys to add. The
// provider's Verifier already holds the central Coord's seed pubkey
// from PEM, so legacy operation continues unchanged. See
// [[dc_transition_plan]] §"Architectural decisions locked" decision 4.
package dirfetch

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/obsideo/obsideo-provider/tokens"
)

// DefaultInterval is the directory refresh cadence — the TTL between
// re-fetches per [[dc_transition_plan]] decision 4. 60s is the trade
// between propagation latency on new-DC registrations and load on
// central Coord. Tunable via Options.Interval if a deployment needs
// different ergonomics.
const DefaultInterval = 60 * time.Second

// Options configures a Refresher. CoordURL, APIKey, CoordPubKey, and
// Verifier are all required; missing values cause New to return nil.
type Options struct {
	// CoordURL is the central Coord base URL ("https://coordinator.obsideo.io").
	// The refresher appends "/v1/provider/directory" to it.
	CoordURL string

	// APIKey is the provider's API key for coord-side authentication.
	// Sent as Authorization: Bearer <APIKey>.
	APIKey string

	// CoordPubKey is the central Coord's Ed25519 public key — the root
	// of trust loaded from coordinator_pub.pem at provider startup. The
	// refresher verifies every directory signature against this key
	// before updating the Verifier.
	CoordPubKey ed25519.PublicKey

	// Verifier is the target for AddKey calls. The refresher never
	// removes keys from the Verifier (additive only); a key that
	// disappears from the directory remains accepted until the
	// provider restarts. Phase 1 has no key-removal flow; Phase 3+
	// can add one if needed.
	Verifier *tokens.Verifier

	// Interval is the refresh period. Defaults to DefaultInterval (60s).
	Interval time.Duration

	// HTTPClient is optional; defaults to a 30-second timeout client.
	// Tests inject a stubbed transport.
	HTTPClient *http.Client

	// Logger is optional; defaults to a stderr logger via the standard
	// log package. Kept simple — no zerolog dependency on the dirfetch
	// path so it stays portable across provider and test harnesses.
	Logger Logger
}

// Logger is the small log surface this package uses. The standard
// log package satisfies it; tests can inject a captured-line logger.
type Logger interface {
	Printf(format string, args ...any)
}

// stdoutLogger is the default logger when Options.Logger is nil. It
// writes through the package-level discardOnNilSink so a refresher
// constructed without a logger doesn't panic in tests that don't care.
type discardLogger struct{}

func (discardLogger) Printf(format string, args ...any) {}

// Refresher polls the central Coord directory and updates the Verifier.
// Construct via New; start via Start.
type Refresher struct {
	opts   Options
	url    string
	client *http.Client
	log    Logger
}

// New returns a configured Refresher. Returns nil and an error string
// when required options are missing — startup wiring should treat that
// as a fatal misconfiguration.
func New(opts Options) (*Refresher, error) {
	if opts.CoordURL == "" {
		return nil, fmt.Errorf("dirfetch: CoordURL is required")
	}
	if opts.APIKey == "" {
		return nil, fmt.Errorf("dirfetch: APIKey is required")
	}
	if len(opts.CoordPubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dirfetch: CoordPubKey must be %d bytes (got %d)", ed25519.PublicKeySize, len(opts.CoordPubKey))
	}
	if opts.Verifier == nil {
		return nil, fmt.Errorf("dirfetch: Verifier is required")
	}
	if opts.Interval == 0 {
		opts.Interval = DefaultInterval
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	logger := opts.Logger
	if logger == nil {
		logger = discardLogger{}
	}
	return &Refresher{
		opts:   opts,
		url:    strings.TrimRight(opts.CoordURL, "/") + "/v1/provider/directory",
		client: client,
		log:    logger,
	}, nil
}

// Start runs the refresh loop until ctx is canceled. Performs an
// immediate refresh on entry so the Verifier picks up registered DCs
// without waiting a full Interval after startup.
func (r *Refresher) Start(ctx context.Context) {
	if added, err := r.RefreshOnce(ctx); err != nil {
		r.log.Printf("dirfetch: initial refresh failed: %v", err)
	} else if added > 0 {
		r.log.Printf("dirfetch: initial refresh added %d new authorized signer(s)", added)
	}

	t := time.NewTicker(r.opts.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			added, err := r.RefreshOnce(ctx)
			if err != nil {
				r.log.Printf("dirfetch: refresh failed: %v (will retry in %s)", err, r.opts.Interval)
				continue
			}
			if added > 0 {
				r.log.Printf("dirfetch: refresh added %d new authorized signer(s)", added)
			}
		}
	}
}

// RefreshOnce fetches the directory once, verifies the signature, and
// applies any new authorized signers to the Verifier. Returns the count
// of newly-added keys (zero if nothing new) plus any error.
//
// On signature-verify failure, returns an error WITHOUT touching the
// Verifier — fail-closed. The provider keeps its previous trust list.
func (r *Refresher) RefreshOnce(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.opts.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch directory: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("directory fetch returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
	if err != nil {
		return 0, fmt.Errorf("read body: %w", err)
	}

	// Parse into a generic map so we can reconstruct the canonical
	// pre-signature payload byte-for-byte. The coord canonicalizes by
	// re-encoding through map[string]any (sorted keys, no whitespace);
	// we mirror that exactly so signatures verify.
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		return 0, fmt.Errorf("parse envelope: %w", err)
	}
	sigB64, _ := envelope["signature"].(string)
	if sigB64 == "" {
		return 0, fmt.Errorf("envelope missing signature")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return 0, fmt.Errorf("decode signature: %w", err)
	}

	// Strip the signature, then re-canonicalize the remaining fields.
	// This is the exact form the coord signed (snapshot.go canonicalMarshal).
	delete(envelope, "signature")
	canonical, err := canonicalMarshal(envelope)
	if err != nil {
		return 0, fmt.Errorf("canonicalize payload: %w", err)
	}

	if !ed25519.Verify(r.opts.CoordPubKey, canonical, sig) {
		// Fail-closed per locked decision 4. Do NOT add any keys; do
		// NOT replace the in-memory trust list. Logged so an operator
		// can investigate (typically caused by a coord-key rotation
		// the provider hasn't picked up yet, or a man-in-the-middle).
		return 0, fmt.Errorf("directory signature invalid (provider's coord pubkey may be stale or directory was tampered with)")
	}

	// Signature is valid → safe to consume the authorized_signers list.
	// A directory without the field (legacy / pre-Phase-1 format) returns
	// nil here; nothing to add, no error.
	rawSigners, _ := envelope["authorized_signers"].([]any)
	added := 0
	for _, e := range rawSigners {
		s, ok := e.(string)
		if !ok || s == "" {
			continue
		}
		pubBytes, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			r.log.Printf("dirfetch: skipping malformed authorized_signer entry %q: %v", s, err)
			continue
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			r.log.Printf("dirfetch: skipping authorized_signer with wrong size (%d bytes)", len(pubBytes))
			continue
		}
		if r.opts.Verifier.AddKey(ed25519.PublicKey(pubBytes)) {
			added++
		}
	}
	return added, nil
}

// canonicalMarshal mirrors coordinator/directory/snapshot.go's
// canonicalMarshal: serialize as JSON, decode into a generic structure,
// re-encode. encoding/json sorts map keys alphabetically on marshal,
// so the output is canonical (sorted keys, no whitespace).
//
// Kept in sync with the coord-side helper. If that one changes the
// canonicalization rules, this one must change to match — drift here
// would break signature verification silently.
func canonicalMarshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}
