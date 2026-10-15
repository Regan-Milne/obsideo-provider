package api

import (
	"net/http"
	"strings"
	"sync/atomic"
)

// Coordinator-challenge authentication (POST /challenge).
//
// /challenge returns a raw chunk of a stored object plus its merkle path, so
// it is authenticated like every other route that returns object bytes.
// Providers serve public HTTPS; network position is not access control.
//
// It reuses the credential providers already verify on every other
// route: a coordinator-signed token (tokens.Verifier, central coord key plus
// any DC keys from the signed directory). The coordinator mints an "audit"
// token per challenge, bound to one merkle root and one provider, with a
// short expiry, and sends it as "Authorization: Bearer <token>".
//
// "audit" is a distinct type on purpose. Customer tokens ("challenge",
// "download") are refused here: their route is /client-challenge, which
// carries the per-account rate limit, and accepting them here would be a way
// around it. Audit tokens are likewise refused on /client-challenge.
//
// Rollout: providers ship with the check OPTIONAL (the default). A presented
// token is always verified, and a bad one is refused; an absent one is served
// as before and counted. Once /health shows unauthenticated == 0 on a box
// while the coordinator is signing, the operator sets
// server.require_challenge_auth: true and unsigned challenges get 401.

const auditTokenType = "audit"

// challengeAuthStats are process-lifetime counters surfaced on /health. They
// exist for one decision: is it safe to flip this box to "required"? That is
// safe exactly when unauthenticated stops growing.
type challengeAuthStats struct {
	authenticated atomic.Int64 // valid audit token presented
	legacy        atomic.Int64 // no token, served because auth is optional
	rejected      atomic.Int64 // refused: missing (when required) or bad token
}

// SetRequireChallengeAuth switches /challenge from optional to required auth.
// Kept separate from New so existing callers need no change.
func (s *Server) SetRequireChallengeAuth(required bool) { s.requireChallengeAuth = required }

func (s *Server) challengeAuthMode() string {
	if s.requireChallengeAuth {
		return "required"
	}
	return "optional"
}

// authorizeChallenge decides whether a /challenge request may be served.
// Returns 0 when allowed, else the HTTP status and message to send.
func (s *Server) authorizeChallenge(r *http.Request, ch auditChallenge) (int, string) {
	if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
		if s.requireChallengeAuth {
			s.challengeAuth.rejected.Add(1)
			return http.StatusUnauthorized, "challenge requires a coordinator audit token"
		}
		s.challengeAuth.legacy.Add(1)
		return 0, ""
	}

	// A token was presented: verify it whatever the mode. Accepting a bad
	// token as "no token" during the optional window would make it decorative.
	status, msg := s.checkAuditToken(r, ch)
	if status != 0 {
		s.challengeAuth.rejected.Add(1)
		return status, msg
	}
	s.challengeAuth.authenticated.Add(1)
	return 0, ""
}

func (s *Server) checkAuditToken(r *http.Request, ch auditChallenge) (int, string) {
	tok, err := bearerToken(r)
	if err != nil {
		return http.StatusUnauthorized, err.Error()
	}
	if s.verifier == nil {
		return http.StatusUnauthorized, "no coordinator key configured; cannot verify audit token"
	}
	claims, err := s.verifier.Verify(tok) // signature + expiry
	if err != nil {
		return http.StatusUnauthorized, err.Error()
	}
	if claims.Type != auditTokenType {
		return http.StatusForbidden, "expected audit token"
	}
	if claims.MerkleRoot == "" || claims.MerkleRoot != ch.MerkleRoot {
		return http.StatusForbidden, "token merkle_root does not match challenge"
	}
	// The token names the provider it was minted for. An empty provider_id is
	// not a wildcard. When this provider's own id is unset (local dev) there
	// is nothing to compare against, matching serveChallenge's body check.
	if claims.ProviderID == "" {
		return http.StatusForbidden, "token has no provider_id"
	}
	if s.providerID != "" && claims.ProviderID != s.providerID {
		return http.StatusForbidden, "token provider_id does not match this provider"
	}
	return 0, ""
}
