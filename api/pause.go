package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/obsideo/obsideo-provider/pausectl"
)

// Circuit-breaker handlers per docs/retention_authority_design.md §4.4
// and §6.7.
//
// POST /control/pause accepts an Envelope (payload + signature) signed
// with the operator cold key. On success the pause is persisted and the
// provider halts all coverage-driven prune decisions until the signal's
// expires_at elapses or is superseded by a higher sequence number.
//
// GET /control/pause returns the current pause state (or {"active":
// false}) for operator dashboards and end-to-end tests.

// handlePauseSignal implements POST /control/pause.
//
// Authorization: cold-key Ed25519 signature over the canonical payload.
// No coord-issued token required — this is deliberately independent of
// coord authority (see design §4.4: "cold key separate from any
// coordinator operational key").
//
// Status-code mapping mirrors the typed errors in pausectl:
//
//	ErrNotConfigured          → 503 (circuit breaker not configured)
//	ErrInvalidEnvelope        → 400
//	ErrInvalidSignatureFormat → 400
//	ErrInvalidSignature       → 401
//	ErrInvalidPayload         → 400
//	ErrWrongType/Version/Scope → 400
//	ErrMalformedTimestamp     → 400
//	ErrExpired                → 400
//	ErrSequenceNotMonotonic   → 409 (conflict — not retryable without a new signal)
//	other                     → 500
func (s *Server) handlePauseSignal(w http.ResponseWriter, r *http.Request) {
	if s.pause == nil || !s.pause.ColdKeyConfigured() {
		writeError(w, http.StatusServiceUnavailable,
			"circuit breaker not configured on this provider")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var env pausectl.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		writeError(w, http.StatusBadRequest, "decode envelope: "+err.Error())
		return
	}

	stored, err := s.pause.Apply(env, time.Now().UTC())
	if err != nil {
		writeError(w, mapPauseError(err), err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "pause_active",
		"sequence_number": stored.Signal.SequenceNumber,
		"expires_at":      stored.Signal.ExpiresAt,
		"scope":           stored.Signal.Scope,
	})
}

// handlePauseStatus implements GET /control/pause. Returns the current
// pause state, or {"active": false} if none is in effect. Unauthenticated
// — the pause state is not sensitive (operators publish it) and the
// endpoint is useful for e2e tests.
func (s *Server) handlePauseStatus(w http.ResponseWriter, r *http.Request) {
	if s.pause == nil || !s.pause.ColdKeyConfigured() {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":     false,
			"configured": false,
		})
		return
	}
	now := time.Now().UTC()
	cur := s.pause.Current(now)
	if cur == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"active":             true,
			"configured":         true,
			"paused":             false,
			"last_sequence_number": s.pause.LastSequence(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     true,
		"configured": true,
		"paused":     true,
		"signal":     cur.Signal,
	})
}

func mapPauseError(err error) int {
	switch {
	case errors.Is(err, pausectl.ErrNotConfigured):
		return http.StatusServiceUnavailable
	case errors.Is(err, pausectl.ErrInvalidEnvelope),
		errors.Is(err, pausectl.ErrInvalidSignatureFormat),
		errors.Is(err, pausectl.ErrInvalidPayload),
		errors.Is(err, pausectl.ErrWrongType),
		errors.Is(err, pausectl.ErrWrongVersion),
		errors.Is(err, pausectl.ErrWrongScope),
		errors.Is(err, pausectl.ErrMalformedTimestamp),
		errors.Is(err, pausectl.ErrExpired):
		return http.StatusBadRequest
	case errors.Is(err, pausectl.ErrInvalidSignature):
		return http.StatusUnauthorized
	case errors.Is(err, pausectl.ErrSequenceNotMonotonic):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
