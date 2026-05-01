package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/obsideo/obsideo-provider/pausectl"
	"github.com/obsideo/obsideo-provider/store"
)

// Tests for POST /control/pause and GET /control/pause (D5). Spec:
// docs/retention_authority_design.md §4.4 / §6.7.
//
// These focus on the HTTP seam: envelope decoding, status-code mapping
// from pausectl errors, and response shape. The deeper invariant tests
// (monotonicity, signature verification, quarantine, etc.) live in
// pausectl/pausectl_test.go; duplicating them here would be wasteful.

type pauseAPIEnv struct {
	srv     *Server
	coldPri ed25519.PrivateKey
}

func newPauseAPIEnv(t *testing.T) *pauseAPIEnv {
	t.Helper()
	coldPub, coldPri, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := pausectl.Load(filepath.Join(dir, "provider"), coldPub)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil, state, "")
	return &pauseAPIEnv{srv: srv, coldPri: coldPri}
}

func (e *pauseAPIEnv) signEnvelope(t *testing.T, s pausectl.Signal) pausectl.Envelope {
	t.Helper()
	payload, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(e.coldPri, payload)
	return pausectl.Envelope{
		Payload:   string(payload),
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func validAPISignal(seq int64) pausectl.Signal {
	now := time.Now().UTC()
	return pausectl.Signal{
		Type:           pausectl.SignalType,
		Version:        pausectl.SignalVersion,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      now.Add(24 * time.Hour).Format(time.RFC3339),
		Scope:          pausectl.SignalScope,
		SequenceNumber: seq,
		Reason:         "api-test",
	}
}

func postPause(t *testing.T, srv *Server, env pausectl.Envelope) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/control/pause", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func getPause(t *testing.T, srv *Server) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/control/pause", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHandlePauseSignal_HappyPath(t *testing.T) {
	e := newPauseAPIEnv(t)
	rec := postPause(t, e.srv, e.signEnvelope(t, validAPISignal(1)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["status"] != "pause_active" {
		t.Errorf("status field: %v", got["status"])
	}
	if _, ok := got["sequence_number"]; !ok {
		t.Error("response missing sequence_number")
	}
	if _, ok := got["expires_at"]; !ok {
		t.Error("response missing expires_at")
	}
}

func TestHandlePauseSignal_NotConfigured(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "provider"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := pausectl.Load(filepath.Join(dir, "provider"), nil) // no cold key
	if err != nil {
		t.Fatal(err)
	}
	srv := New(st, nil, state, "")

	// Signature doesn't matter — should 503 before touching it.
	rec := postPause(t, srv, pausectl.Envelope{Payload: "{}", Signature: "x"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no cold key: code %d want 503, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandlePauseSignal_NilPauseState(t *testing.T) {
	// Explicit nil *pausectl.State (pre-Phase-1 servers built with the
	// old two-arg New()). The handler must 503 without panicking.
	dir := t.TempDir()
	st, _ := store.New(filepath.Join(dir, "provider"))
	srv := New(st, nil, nil, "")

	rec := postPause(t, srv, pausectl.Envelope{Payload: "{}", Signature: "x"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("nil pause state: code %d want 503", rec.Code)
	}
}

func TestHandlePauseSignal_StatusMapping(t *testing.T) {
	e := newPauseAPIEnv(t)

	// Accept seq=5 so we have a baseline for the monotonicity test.
	if rec := postPause(t, e.srv, e.signEnvelope(t, validAPISignal(5))); rec.Code != http.StatusOK {
		t.Fatalf("baseline accept: %d body=%s", rec.Code, rec.Body.String())
	}

	cases := []struct {
		name     string
		build    func() pausectl.Envelope
		wantCode int
	}{
		{
			"bad json body",
			func() pausectl.Envelope {
				// Not actually called via signEnvelope; we'll override.
				return pausectl.Envelope{}
			},
			http.StatusBadRequest,
		},
		{
			"wrong signature",
			func() pausectl.Envelope {
				_, otherPri, _ := ed25519.GenerateKey(rand.Reader)
				payload, _ := json.Marshal(validAPISignal(6))
				return pausectl.Envelope{
					Payload:   string(payload),
					Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(otherPri, payload)),
				}
			},
			http.StatusUnauthorized,
		},
		{
			"replay at lower seq",
			func() pausectl.Envelope {
				return e.signEnvelope(t, validAPISignal(4))
			},
			http.StatusConflict,
		},
		{
			"wrong scope",
			func() pausectl.Envelope {
				s := validAPISignal(7)
				s.Scope = "all"
				return e.signEnvelope(t, s)
			},
			http.StatusBadRequest,
		},
		{
			"expired",
			func() pausectl.Envelope {
				s := validAPISignal(8)
				s.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
				return e.signEnvelope(t, s)
			},
			http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if tc.name == "bad json body" {
				req := httptest.NewRequest(http.MethodPost, "/control/pause",
					bytes.NewReader([]byte("{not json")))
				rec = httptest.NewRecorder()
				e.srv.Handler().ServeHTTP(rec, req)
			} else {
				rec = postPause(t, e.srv, tc.build())
			}
			if rec.Code != tc.wantCode {
				t.Errorf("code=%d want=%d body=%s", rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}
}

func TestHandlePauseStatus(t *testing.T) {
	e := newPauseAPIEnv(t)

	// Fresh — configured but not paused.
	rec := getPause(t, e.srv)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code: %d", rec.Code)
	}
	var fresh map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &fresh); err != nil {
		t.Fatal(err)
	}
	if fresh["configured"] != true {
		t.Errorf("configured should be true: %v", fresh)
	}
	if fresh["paused"] != false {
		t.Errorf("paused should be false before any signal: %v", fresh)
	}

	// Activate and re-check.
	if _, err := e.srv.pause.Apply(e.signEnvelope(t, validAPISignal(1)), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	rec = getPause(t, e.srv)
	var active map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &active); err != nil {
		t.Fatal(err)
	}
	if active["paused"] != true {
		t.Errorf("paused should be true after Apply: %v", active)
	}
	sig, ok := active["signal"].(map[string]any)
	if !ok {
		t.Fatalf("response missing signal object: %v", active)
	}
	// JSON numbers decode to float64 by default.
	if seq, _ := sig["sequence_number"].(float64); seq != 1 {
		t.Errorf("signal.sequence_number: %v", sig["sequence_number"])
	}
}

func TestHandlePauseStatus_Unconfigured(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.New(filepath.Join(dir, "provider"))
	srv := New(st, nil, nil, "")

	rec := getPause(t, srv)
	if rec.Code != http.StatusOK {
		t.Errorf("code: %d", rec.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["configured"] != false {
		t.Errorf("configured should be false: %v", got)
	}
	if got["active"] != false {
		t.Errorf("active should be false: %v", got)
	}
}
