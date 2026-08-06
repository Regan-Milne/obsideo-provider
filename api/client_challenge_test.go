package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/identity"
	"github.com/obsideo/obsideo-provider/store"
	"github.com/obsideo/obsideo-provider/tokens"
)

const clientChalMerkle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// clientChalEnv: server with a signing identity, a token verifier with a
// known coord key, and one stored object.
func clientChalEnv(t *testing.T) (*Server, ed25519.PrivateKey, *identity.Identity) {
	t.Helper()
	tempDir := t.TempDir()
	st, err := store.New(filepath.Join(tempDir, "provider"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := st.Put(clientChalMerkle, bytes.Repeat([]byte("a"), (2*store.DefaultChunkSize)+17), store.DefaultChunkSize); err != nil {
		t.Fatalf("Put: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ident, err := identity.LoadOrCreate(tempDir)
	if err != nil {
		t.Fatal(err)
	}
	server := New(st, tokens.NewVerifierForTesting(pub), nil, "test-provider-id", true)
	server.SetProofSigner(ident)
	return server, priv, ident
}

func clientChallengeReq(t *testing.T, token string, merkle string) *http.Request {
	t.Helper()
	body, _ := json.Marshal(auditChallenge{
		Version:      proofVersionV1,
		ChallengeID:  "client-ch-1",
		MerkleRoot:   merkle,
		ChunkIndex:   0,
		Nonce:        "c11e47deadbeef00",
		ExpiresAt:    time.Now().Add(time.Minute).Unix(),
		ProofVersion: proofVersionV1,
	})
	req := httptest.NewRequest(http.MethodPost, "/client-challenge", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func challengeClaims(typ, merkle string) tokens.Claims {
	return tokens.Claims{
		Type:       typ,
		MerkleRoot: merkle,
		AccountID:  "acct-1",
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().Add(time.Minute).Unix(),
	}
}

// TestClientChallenge_HappyPath — a customer with a challenge token gets a
// SIGNED response they can verify against the provider's key. The full
// sovereign-verification loop at the unit level.
func TestClientChallenge_HappyPath(t *testing.T) {
	server, coordPriv, ident := clientChalEnv(t)
	tok := signTestToken(t, coordPriv, challengeClaims("challenge", clientChalMerkle))

	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, clientChallengeReq(t, tok, clientChalMerkle))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	var resp auditResponse
	if err := json.Unmarshal(res.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Signature == "" {
		t.Fatal("client-challenge response unsigned")
	}
	if !verifyResponseSig(t, resp, 0, ident.PublicKey()) {
		t.Fatal("client-challenge signature did not verify")
	}
}

// TestClientChallenge_DownloadTokenAccepted — a download token is a strictly
// stronger capability for the same merkle, so it is accepted.
func TestClientChallenge_DownloadTokenAccepted(t *testing.T) {
	server, coordPriv, _ := clientChalEnv(t)
	tok := signTestToken(t, coordPriv, challengeClaims("download", clientChalMerkle))
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, clientChallengeReq(t, tok, clientChalMerkle))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
}

// TestClientChallenge_AuthRequired — no token is 401. This is the difference
// between /client-challenge and the legacy /challenge route.
func TestClientChallenge_AuthRequired(t *testing.T) {
	server, _, _ := clientChalEnv(t)
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, clientChallengeReq(t, "", clientChalMerkle))
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Code)
	}
}

// TestClientChallenge_WrongTypeRejected — an upload token must not authorize
// challenges.
func TestClientChallenge_WrongTypeRejected(t *testing.T) {
	server, coordPriv, _ := clientChalEnv(t)
	tok := signTestToken(t, coordPriv, challengeClaims("upload", clientChalMerkle))
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, clientChallengeReq(t, tok, clientChalMerkle))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.Code)
	}
}

// TestClientChallenge_MerkleMismatchRejected — the token authorizes exactly
// one object; challenging a different one is forbidden. This is the check
// that stops one valid token becoming a fleet-wide chunk-reading key.
func TestClientChallenge_MerkleMismatchRejected(t *testing.T) {
	server, coordPriv, _ := clientChalEnv(t)
	other := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	tok := signTestToken(t, coordPriv, challengeClaims("challenge", other))
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, clientChallengeReq(t, tok, clientChalMerkle))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.Code)
	}
}

// TestClientChallenge_RateLimited — the (account, merkle) window caps at
// clientChallengeLimit, then 429.
func TestClientChallenge_RateLimited(t *testing.T) {
	server, coordPriv, _ := clientChalEnv(t)
	tok := signTestToken(t, coordPriv, challengeClaims("challenge", clientChalMerkle))
	for i := 0; i < clientChallengeLimit; i++ {
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, clientChallengeReq(t, tok, clientChalMerkle))
		if res.Code != http.StatusOK {
			t.Fatalf("challenge %d: status = %d, want 200", i, res.Code)
		}
	}
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, clientChallengeReq(t, tok, clientChalMerkle))
	if res.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 after %d challenges", res.Code, clientChallengeLimit)
	}
}

// TestChallengeRateLimiter_WindowResets — a new window clears the counters.
func TestChallengeRateLimiter_WindowResets(t *testing.T) {
	l := newChallengeRateLimiter()
	now := time.Now()
	for i := 0; i < clientChallengeLimit; i++ {
		if !l.allow("k", now) {
			t.Fatalf("attempt %d denied inside window", i)
		}
	}
	if l.allow("k", now) {
		t.Fatal("over-limit attempt allowed")
	}
	if !l.allow("k", now.Add(clientChallengeWindow+time.Second)) {
		t.Fatal("attempt denied after window reset")
	}
}

// TestLegacyChallengeRouteStillOpen — the coord path must stay token-free
// through the mixed-fleet rollout; a tokenless /challenge succeeds.
func TestLegacyChallengeRouteStillOpen(t *testing.T) {
	server, _, _ := clientChalEnv(t)
	body, _ := json.Marshal(auditChallenge{
		Version: proofVersionV1, ChallengeID: "coord-ch", MerkleRoot: clientChalMerkle,
		ChunkIndex: 0, Nonce: "deadbeef",
		ExpiresAt: time.Now().Add(time.Minute).Unix(), ProofVersion: proofVersionV1,
	})
	req := httptest.NewRequest(http.MethodPost, "/challenge", bytes.NewReader(body))
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("legacy /challenge status = %d, want 200 (coord sends no token)", res.Code)
	}
}

var _ = fmt.Sprintf // keep fmt import if assertions above change
