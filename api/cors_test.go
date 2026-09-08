package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsRouter(t *testing.T, enabled bool, origins []string) http.Handler {
	t.Helper()
	s := &Server{}
	s.SetCORS(enabled, origins)
	return s.Handler()
}

func TestCORSPreflightOnBrowserRoute(t *testing.T) {
	h := corsRouter(t, true, []string{"*"})
	for _, p := range []string{"/upload/abc", "/upload/abc/chunk", "/download/abc", "/delete/abc", "/client-challenge", "/health"} {
		req := httptest.NewRequest(http.MethodOptions, p, nil)
		req.Header.Set("Origin", "https://obsideo.io")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Errorf("%s: preflight status = %d, want 204", p, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("%s: Allow-Origin = %q, want *", p, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Headers"); got != corsAllowHeaders {
			t.Errorf("%s: Allow-Headers = %q", p, got)
		}
		if rec.Header().Get("Access-Control-Max-Age") == "" {
			t.Errorf("%s: missing Max-Age", p)
		}
	}
}

func TestCORSNeverOnCoordinatorRoutes(t *testing.T) {
	h := corsRouter(t, true, []string{"*"})
	for _, p := range []string{"/challenge", "/replicate", "/control/pause"} {
		req := httptest.NewRequest(http.MethodOptions, p, nil)
		req.Header.Set("Origin", "https://obsideo.io")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s: coordinator-only route must not carry CORS headers", p)
		}
		if rec.Code == http.StatusNoContent {
			t.Errorf("%s: preflight must not be answered for a coordinator-only route (got 204)", p)
		}
	}
}

func TestCORSActualRequestGetsOriginAndExpose(t *testing.T) {
	h := corsRouter(t, true, []string{"*"})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://example.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" || rec.Header().Get("Access-Control-Expose-Headers") != corsExposeHeader {
		t.Errorf("actual request headers = %v", rec.Header())
	}
}

func TestCORSNoOriginPassesThroughUntouched(t *testing.T) {
	h := corsRouter(t, true, []string{"*"})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("non-browser request must be untouched: code=%d hdr=%v", rec.Code, rec.Header())
	}
}

func TestCORSRestrictedOrigins(t *testing.T) {
	h := corsRouter(t, true, []string{"https://obsideo.io"})
	ok := httptest.NewRequest(http.MethodOptions, "/upload/x", nil)
	ok.Header.Set("Origin", "https://OBSIDEO.io")
	ok.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ok)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://OBSIDEO.io" || rec.Header().Get("Vary") != "Origin" {
		t.Errorf("allowed origin should be echoed with Vary: %v", rec.Header())
	}
	bad := httptest.NewRequest(http.MethodOptions, "/upload/x", nil)
	bad.Header.Set("Origin", "https://evil.test")
	bad.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, bad)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("disallowed origin must get no Allow-Origin: %v", rec.Header())
	}
}

func TestCORSDisabled(t *testing.T) {
	h := corsRouter(t, false, []string{"*"})
	req := httptest.NewRequest(http.MethodOptions, "/upload/x", nil)
	req.Header.Set("Origin", "https://obsideo.io")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" || rec.Code == http.StatusNoContent {
		t.Errorf("cors disabled must behave like v1-6: code=%d hdr=%v", rec.Code, rec.Header())
	}
}
