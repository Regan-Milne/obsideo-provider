package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Client-issued possession challenges.
//
// The customer's client challenges this provider directly and verifies the
// response against the merkle root IT computed at upload, so the check needs
// no trust in the coordinator: the coordinator can refuse to mint a token
// (deny availability, which is observable), but it cannot fake a passing
// proof, because the verification math runs client-side against a value only
// the customer holds and the response is signed by this provider's key.
//
// Auth is the same model as /download: a coord-issued token bound to the
// merkle root. A "challenge" token is the purpose-built type; a "download"
// token is also accepted because it is a strictly stronger capability for
// the same object (a holder could fetch every byte and self-verify anyway).
// The pre-existing UNAUTHENTICATED /challenge route is unchanged — the coord
// challenger sends no token, and mixed-fleet rollout must not break it.
//
// Rate limiting: a fixed-window per (account, merkle) counter. A challenge
// reads one chunk (~1 MiB) from disk; without a cap the route would be a
// disk-I/O amplifier for anyone with a valid token. The window is deliberately
// generous — real verification needs a handful of challenges, not hundreds.

const (
	// clientChallengeLimit is the max client challenges per (account, merkle)
	// per window. 30/min supports aggressive multi-chunk verification sweeps
	// while capping sustained disk-read amplification from a single token.
	clientChallengeLimit  = 30
	clientChallengeWindow = time.Minute
)

// challengeRateLimiter is a fixed-window counter. Windows reset lazily on
// first hit after expiry; the map is pruned opportunistically at reset so a
// long-lived process does not accumulate dead (account, merkle) entries.
type challengeRateLimiter struct {
	mu      sync.Mutex
	window  time.Time
	entries map[string]int
}

func newChallengeRateLimiter() *challengeRateLimiter {
	return &challengeRateLimiter{entries: make(map[string]int)}
}

// allow reports whether key may issue one more challenge in the current
// window, counting the attempt if allowed.
func (l *challengeRateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) >= clientChallengeWindow {
		l.window = now
		l.entries = make(map[string]int) // new window: drop all counts
	}
	if l.entries[key] >= clientChallengeLimit {
		return false
	}
	l.entries[key]++
	return true
}

// handleClientChallenge is POST /client-challenge: an authenticated,
// rate-limited path for a customer to challenge this provider directly.
// Body is the same auditChallenge shape the coord uses; the response is the
// same (signed) auditResponse — one wire format for both audiences, so the
// customer-side verifier and the coord-side verifier are the same code.
func (s *Server) handleClientChallenge(w http.ResponseWriter, r *http.Request) {
	tok, err := bearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	claims, err := s.verifier.Verify(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if claims.Type != "challenge" && claims.Type != "download" {
		writeError(w, http.StatusForbidden, "expected challenge or download token")
		return
	}

	var ch auditChallenge
	if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
		writeError(w, http.StatusBadRequest, "decode body: "+err.Error())
		return
	}

	// The token authorizes exactly one object. A mismatch is a forbidden
	// request, not a malformed one — the caller is trying to challenge an
	// object their token does not cover.
	if claims.MerkleRoot == "" || claims.MerkleRoot != ch.MerkleRoot {
		writeError(w, http.StatusForbidden, "token merkle_root does not match challenge")
		return
	}

	if !s.clientChallenges.allow(claims.AccountID+"/"+ch.MerkleRoot, time.Now()) {
		writeError(w, http.StatusTooManyRequests, "client challenge rate limit exceeded; retry next window")
		return
	}

	s.serveChallenge(w, ch)
}
