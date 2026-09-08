package api

import (
	"net/http"
	"strings"
)

// CORS for browser clients (provider-v1-7).
//
// WHY: a browser cannot upload to, download from, or challenge a provider
// unless the provider answers the preflight OPTIONS request and marks its
// responses with Access-Control-Allow-Origin. Until v1-7 nothing on the
// network was browser-to-provider (the SDK, the gateway and Nest's backend
// are all server-side), so this never mattered. The obsideo.io test page
// changes that: it encrypts in the browser and talks to nodes directly.
//
// WHAT IS EXPOSED: only the customer-facing routes, which are all already
// authenticated by a coordinator-issued token (upload, download,
// client-challenge) or by the customer's own Ed25519 signature (delete),
// plus /health. The coordinator-only routes (/challenge, /replicate,
// /control/*) never get CORS headers: a browser has no business calling
// them, and the firewall guidance in OPERATOR_SETUP still applies.
//
// WHY "*" IS THE DEFAULT: CORS protects users of a site from having their
// ambient credentials (cookies) replayed by another site. Nothing here uses
// cookies; every request carries an explicit bearer token in a header that
// the calling page must already possess. Restricting origins would only
// decide WHICH sites may build a UI over the network, which is not a
// provider's decision to make for its customers. Operators who want to
// restrict anyway can list origins in config.yaml (server.cors_allowed_origins)
// or set server.cors_enabled: false.

const (
	corsAllowMethods = "GET, POST, OPTIONS"
	corsAllowHeaders = "Authorization, Content-Type, Range"
	corsExposeHeader = "Content-Range, Accept-Ranges, Content-Length"
	corsMaxAge       = "600"
)

// corsBrowserRoute reports whether a path is one a browser client may call.
func corsBrowserRoute(p string) bool {
	switch {
	case p == "/health", p == "/client-challenge":
		return true
	case strings.HasPrefix(p, "/upload/"), strings.HasPrefix(p, "/download/"), strings.HasPrefix(p, "/delete/"):
		return true
	}
	return false
}

// corsMiddleware adds CORS headers on browser-facing routes and answers
// preflight requests for them. origins is the allow-list; a single "*"
// allows any origin. Requests without an Origin header pass through untouched.
func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	any := false
	allowed := map[string]bool{}
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "*" {
			any = true
		} else if o != "" {
			allowed[strings.ToLower(o)] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" || !corsBrowserRoute(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			permitted := any || allowed[strings.ToLower(origin)]
			preflight := r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
			if !permitted {
				if preflight {
					// Deny quietly: no CORS headers means the browser blocks it.
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			h := w.Header()
			if any {
				h.Set("Access-Control-Allow-Origin", "*")
			} else {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Add("Vary", "Origin")
			}
			if preflight {
				h.Set("Access-Control-Allow-Methods", corsAllowMethods)
				h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
				h.Set("Access-Control-Max-Age", corsMaxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			h.Set("Access-Control-Expose-Headers", corsExposeHeader)
			next.ServeHTTP(w, r)
		})
	}
}
