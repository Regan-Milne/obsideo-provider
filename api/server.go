package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/Regan-Milne/obsideo-provider/pausectl"
	"github.com/Regan-Milne/obsideo-provider/store"
	"github.com/Regan-Milne/obsideo-provider/tokens"
)

// Server is the provider HTTP server.
type Server struct {
	store    *store.Store
	verifier *tokens.Verifier
	nonces   *nonceCache
	pause    *pausectl.State // nil when no cold key configured
}

// New creates a Server. Pass nil for pause to disable the circuit
// breaker (POST /control/pause will 503 and IsPaused always returns
// false) — this matches pre-Phase-1 deployments that have not yet
// configured a cold-key pubkey.
func New(st *store.Store, v *tokens.Verifier, pause *pausectl.State) *Server {
	return &Server{
		store:    st,
		verifier: v,
		nonces:   newNonceCache(deleteCommandNonceTTL),
		pause:    pause,
	}
}

// Handler builds and returns the router.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()

	// Authenticated (coordinator-issued JWT required).
	r.Post("/upload/{merkle}", s.handleUpload)
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

	// Internal — called by coordinator; restrict at firewall in production.
	r.Post("/challenge", s.handleChallenge)
	r.Post("/replicate", s.handleReplicate)
	r.Delete("/objects/{merkle}", s.handleDelete)
	r.Get("/list", s.handleList)

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
