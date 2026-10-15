package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/tokens"
)

// Coordinator-challenge authentication (POST /challenge).
//
// These tests pin the four outcomes the rollout depends on: an unsigned
// challenge is refused once auth is required, an expired token is refused, a
// token minted for a different provider is refused, and a valid audit token is
// served for both raw (v2) and compact (v4) proofs. The legacy-window cases
// pin the other half: until the operator flips the flag, an unsigned
// challenge is still answered, so a provider upgraded ahead of the
// coordinator keeps earning.

// auditEnv reuses clientChalEnv (stored object + known coord key + signing
// identity) and sets the challenge-auth mode.
func auditEnv(t *testing.T, required bool) (*Server, ed25519.PrivateKey) {
	t.Helper()
	server, coordPriv, _ := clientChalEnv(t)
	server.SetRequireChallengeAuth(required)
	return server, coordPriv
}

func auditClaims(merkle, providerID string, exp time.Time) tokens.Claims {
	return tokens.Claims{
		Type:       auditTokenType,
		MerkleRoot: merkle,
		ProviderID: providerID,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  exp.Unix(),
	}
}

func coordChallengeReq(t *testing.T, token, merkle string, proofVersion int) *http.Request {
	t.Helper()
	body, _ := json.Marshal(auditChallenge{
		Version:      proofVersion,
		ChallengeID:  "audit-ch-1",
		MerkleRoot:   merkle,
		ProviderID:   "test-provider-id",
		ChunkIndex:   1,
		BlockIndex:   0,
		Nonce:        "a0d17deadbeef000",
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
		ProofVersion: proofVersion,
	})
	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// serve routes through Handler() so the test covers the real router path,
// not just the handler function.
func serve(server *Server, req *http.Request) *httptest.ResponseRecorder {
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	return res
}

func TestChallengeAuth_Required_UnsignedRejected(t *testing.T) {
	server, _ := auditEnv(t, true)
	res := serve(server, coordChallengeReq(t, "", clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", res.Code, res.Body.String())
	}
	if got := server.challengeAuth.rejected.Load(); got != 1 {
		t.Fatalf("rejected counter = %d, want 1", got)
	}
}

func TestChallengeAuth_Required_ExpiredRejected(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(-time.Second)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", res.Code, res.Body.String())
	}
}

func TestChallengeAuth_Required_WrongProviderRejected(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "some-other-provider", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", res.Code, res.Body.String())
	}
}

// A token with no provider_id is not a wildcard: it is refused even though
// it would match nothing in particular.
func TestChallengeAuth_Required_EmptyProviderRejected(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", res.Code, res.Body.String())
	}
}

func TestChallengeAuth_Required_WrongMerkleRejected(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	other := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tok := signTestToken(t, coordPriv, auditClaims(other, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", res.Code, res.Body.String())
	}
}

// Customer tokens (challenge/download) are refused here: /client-challenge is
// their route, and it is the one with the per-account rate limit. Accepting
// them on /challenge would be a way around that limit.
func TestChallengeAuth_Required_CustomerTokenTypesRejected(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	for _, typ := range []string{"challenge", "download", "upload"} {
		c := auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute))
		c.Type = typ
		tok := signTestToken(t, coordPriv, c)
		res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
		if res.Code != http.StatusForbidden {
			t.Fatalf("type %q: status = %d, want 403; body = %s", typ, res.Code, res.Body.String())
		}
	}
}

func TestChallengeAuth_Required_ForeignKeyRejected(t *testing.T) {
	server, _ := auditEnv(t, true)
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	tok := signTestToken(t, foreign, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", res.Code, res.Body.String())
	}
}

func TestChallengeAuth_Required_ValidPasses_V1Raw(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", res.Code, res.Body.String())
	}
	var resp auditResponse
	if err := json.Unmarshal(res.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ProofVersion != proofVersionV1 || resp.ChunkIndex != 1 || resp.Signature == "" {
		t.Fatalf("unexpected response: proof_version=%d chunk=%d signed=%v", resp.ProofVersion, resp.ChunkIndex, resp.Signature != "")
	}
	if got := server.challengeAuth.authenticated.Load(); got != 1 {
		t.Fatalf("authenticated counter = %d, want 1", got)
	}
}

// Compact proofs are ~78% of production challenges; auth must not change
// their shape.
func TestChallengeAuth_Required_ValidPasses_V4Compact(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionCompact))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", res.Code, res.Body.String())
	}
	var resp auditResponse
	if err := json.Unmarshal(res.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ProofVersion != proofVersionCompact {
		t.Fatalf("proof_version = %d, want %d", resp.ProofVersion, proofVersionCompact)
	}
}

// A provider whose own provider_id is unset (local dev) cannot check the
// token's target, so it skips that comparison, matching the existing
// body-level provider_id rule in serveChallenge.
func TestChallengeAuth_Required_UnsetLocalProviderIDSkipsTargetCheck(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	server.providerID = ""
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "whatever", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", res.Code, res.Body.String())
	}
}

func TestChallengeAuth_Required_NoVerifierRejects(t *testing.T) {
	server, coordPriv := auditEnv(t, true)
	server.verifier = nil
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", res.Code, res.Body.String())
	}
}

// --- legacy window (flag off, the default) ---

func TestChallengeAuth_Legacy_UnsignedStillServed(t *testing.T) {
	server, _ := auditEnv(t, false)
	res := serve(server, coordChallengeReq(t, "", clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", res.Code, res.Body.String())
	}
	if got := server.challengeAuth.legacy.Load(); got != 1 {
		t.Fatalf("legacy counter = %d, want 1", got)
	}
}

// A presented token is always checked, even in the legacy window. Falling
// back to "unsigned is fine" on a bad token would make the token decorative.
func TestChallengeAuth_Legacy_BadTokenStillRejected(t *testing.T) {
	server, coordPriv := auditEnv(t, false)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "some-other-provider", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", res.Code, res.Body.String())
	}
	if got := server.challengeAuth.legacy.Load(); got != 0 {
		t.Fatalf("legacy counter = %d, want 0 (a bad token is not a legacy request)", got)
	}
}

func TestChallengeAuth_Legacy_ValidTokenCounted(t *testing.T) {
	server, coordPriv := auditEnv(t, false)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionCompact))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", res.Code, res.Body.String())
	}
	if got := server.challengeAuth.authenticated.Load(); got != 1 {
		t.Fatalf("authenticated counter = %d, want 1", got)
	}
}

// An audit token is coordinator-internal and is not accepted on the customer
// route, which keeps the two audiences' credentials separate.
func TestChallengeAuth_AuditTokenRefusedOnClientChallenge(t *testing.T) {
	server, coordPriv := auditEnv(t, false)
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	res := serve(server, clientChallengeReq(t, tok, clientChalMerkle))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", res.Code, res.Body.String())
	}
}

// /health reports the mode and counters so the rollout can confirm, per box,
// that every challenge the coordinator sends is authenticated BEFORE the
// flag flips.
func TestChallengeAuth_HealthReportsCounters(t *testing.T) {
	server, coordPriv := auditEnv(t, false)
	serve(server, coordChallengeReq(t, "", clientChalMerkle, proofVersionV1))
	tok := signTestToken(t, coordPriv, auditClaims(clientChalMerkle, "test-provider-id", time.Now().Add(time.Minute)))
	serve(server, coordChallengeReq(t, tok, clientChalMerkle, proofVersionV1))

	res := serve(server, httptest.NewRequest(http.MethodGet, "/health", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("health status = %d", res.Code)
	}
	var h struct {
		Status        string `json:"status"`
		ChallengeAuth struct {
			Mode            string `json:"mode"`
			Authenticated   int64  `json:"authenticated"`
			Unauthenticated int64  `json:"unauthenticated"`
			Rejected        int64  `json:"rejected"`
		} `json:"challenge_auth"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" || h.ChallengeAuth.Mode != "optional" ||
		h.ChallengeAuth.Authenticated != 1 || h.ChallengeAuth.Unauthenticated != 1 || h.ChallengeAuth.Rejected != 0 {
		t.Fatalf("unexpected health body: %s", res.Body.String())
	}
}
