package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/obsideo/obsideo-provider/pausectl"
	"github.com/obsideo/obsideo-provider/store"
	"github.com/obsideo/obsideo-provider/tokens"
)

// ProofSigner signs the canonical payload of a challenge response so a third
// party can attribute the proof to this provider rather than trusting the
// coordinator. *identity.Identity satisfies it. A nil signer means the
// provider does not sign — responses go out exactly as they did before signing
// existed (legacy / local-dev), which keeps mixed-fleet behavior graceful.
type ProofSigner interface {
	Sign(payload []byte) []byte
	KeyID() string
}

// Server is the provider HTTP server.
type Server struct {
	store                  *store.Store
	verifier               *tokens.Verifier
	nonces                 *nonceCache
	pause                  *pausectl.State // nil when no cold key configured
	providerID             string          // echoed in challenge responses; "" disables strict provider_id checks
	acceptUncontractedData bool            // operator policy: accept uploads from non-contracted accounts
	signer                 ProofSigner     // nil = do not sign challenge responses (legacy/dev)
	clientChallenges       *challengeRateLimiter
	corsEnabled            bool
	corsOrigins            []string
	requireChallengeAuth   bool // false = audit token optional on /challenge (rollout window); see challenge_auth.go
	challengeAuth          challengeAuthStats
}

// SetProofSigner attaches a signing identity so challenge responses are signed.
// Additive and optional: left unset, the server behaves exactly as before.
// Kept separate from New so the many existing New callers (and their tests)
// need no change.
func (s *Server) SetProofSigner(signer ProofSigner) { s.signer = signer }

// New creates a Server. Pass nil for pause to disable the circuit
// breaker (POST /control/pause will 503 and IsPaused always returns
// false) — this matches pre-Phase-1 deployments that have not yet
// configured a cold-key pubkey. providerID is echoed in challenge
// responses and used to reject mis-targeted challenges; pass "" to
// skip the targeting check (test/local-dev shape). acceptUncontractedData
// gates the upload handler — when false, uploads with claims.Contracted
// == false are rejected with HTTP 403 before any bytes touch disk.
// Default-true at the config layer; pass true here to preserve existing
// permissive behavior.
func New(st *store.Store, v *tokens.Verifier, pause *pausectl.State, providerID string, acceptUncontractedData bool) *Server {
	return &Server{
		store:                  st,
		verifier:               v,
		nonces:                 newNonceCache(deleteCommandNonceTTL),
		pause:                  pause,
		providerID:             providerID,
		acceptUncontractedData: acceptUncontractedData,
		clientChallenges:       newChallengeRateLimiter(),
		corsEnabled:            true,
		corsOrigins:            []string{"*"},
	}
}

// SetCORS configures browser access (see cors.go). Called from cmd/start
// with server.cors_enabled / server.cors_allowed_origins. Defaults: enabled, "*".
func (s *Server) SetCORS(enabled bool, origins []string) {
	s.corsEnabled = enabled
	if len(origins) == 0 {
		origins = []string{"*"}
	}
	s.corsOrigins = origins
}

// Handler builds and returns the router.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()

	// Browser access (provider-v1-7): preflight + CORS headers on the
	// customer-facing routes only. See cors.go for what and why.
	if s.corsEnabled {
		r.Use(corsMiddleware(s.corsOrigins))
	}

	// Coordinator-issued JWT required. Note there is no router-level
	// middleware here: each handler below calls bearerToken + verifier.
	// Verify itself. Adding a route to this group does NOT authenticate
	// it — an unauthenticated DELETE /objects/{merkle} sat in the
	// "internal" group below for months on exactly that assumption.
	r.Post("/upload/{merkle}", s.handleUpload)
	// Chunked upload (used by SDK for files >10 MB). Ported from
	// provider/api/chunked.go; same wire protocol the SDK has been using
	// in production since 2026-04-06 (legacy commit dd22176).
	r.Post("/upload/{merkle}/chunk", s.handleUploadChunk)
	r.Post("/upload/{merkle}/finalize", s.handleUploadFinalize)
	r.Get("/upload/{merkle}/status", s.handleUploadStatus)
	r.Get("/download/{merkle}", s.handleDownload)

	// User-signed delete (retention-authority Phase 1). No coord token
	// required; authorization is the customer's Ed25519 signature over
	// the canonical delete command. See docs/retention_authority_design.md §6.3.
	r.Post("/delete/{merkle}", s.handleDeleteSigned)

	// Circuit breaker (retention-authority Phase 1, design §4.4 / §6.7).
	// No coord token required; authorization is the cold-key Ed25519
	// signature over the canonical pause-signal payload.
	r.Post("/control/pause", s.handlePauseSignal)
	r.Get("/control/pause", s.handlePauseStatus)

	// Client-issued possession challenge (signed-proofs Level 2, "sovereign
	// verification"). Token-authenticated + rate-limited; same wire format
	// as /challenge so one verifier serves both audiences.
	r.Post("/client-challenge", s.handleClientChallenge)

	// Coordinator audit challenge. Authenticated by a coordinator-signed
	// "audit" token (optional during rollout, then required by config); see
	// challenge_auth.go. Do not rely on firewalling: providers serve public
	// HTTPS and this route returns object bytes.
	r.Post("/challenge", s.handleChallenge)
	// Internal — called by coordinator; restrict at firewall in production.
	r.Post("/replicate", s.handleReplicate)

	// DELIBERATELY ABSENT — do not re-add:
	//
	//   DELETE /objects/{merkle}   (was s.handleDelete)
	//   GET    /list               (was s.handleList)
	//
	// Both were unauthenticated. Together they were a complete remote
	// wipe primitive: GET /list to enumerate every merkle root held,
	// then DELETE /objects/{root} per root. Providers serve public
	// HTTPS, so this was reachable from anywhere on the internet with
	// no credential of any kind. Verified live on the whole fleet
	// 2026-07-31.
	//
	// Erase is now expressible only as POST /delete/{merkle}, which
	// requires the customer's Ed25519 signature over the canonical
	// delete command verified against this provider's own ownership
	// record (see delete.go). That is the design principle: the
	// coordinator may CARRY a signed delete but cannot FORGE one, so
	// no coord compromise yields erase authority.
	//
	// Neither route had a production caller. /list was read only by
	// coordinator/gc's coord-initiated delete path, which is removed in
	// this same change; the coordinator learns provider contents by
	// provider push via POST /v1/provider/roots/status.

	// Health.
	r.Get("/health", s.handleHealth)

	return r
}

// --- shared helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, error) {
	hdr := r.Header.Get("Authorization")
	if len(hdr) < 8 || hdr[:7] != "Bearer " {
		return "", fmt.Errorf("missing or malformed Authorization header")
	}
	return hdr[7:], nil
}
