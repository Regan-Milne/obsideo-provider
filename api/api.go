package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/Regan-Milne/obsideo-provider/config"
	"github.com/Regan-Milne/obsideo-provider/file_system"
	"github.com/Regan-Milne/obsideo-provider/tokens"
	"github.com/rs/cors"
	"github.com/rs/zerolog/log"
)

type Server struct {
	cfg  *config.Config
	fs   *file_system.FileSystem
	ver  *tokens.Verifier
	srv  *http.Server
}

func New(cfg *config.Config, fs *file_system.FileSystem, ver *tokens.Verifier) *Server {
	return &Server{cfg: cfg, fs: fs, ver: ver}
}

func (s *Server) Start() error {
	r := mux.NewRouter()

	// Authenticated endpoints (upload/download require valid coordinator token)
	r.HandleFunc("/upload/{merkle}/chunk", s.handleUploadChunk).Methods(http.MethodPost)
	r.HandleFunc("/upload/{merkle}/finalize", s.handleUploadFinalize).Methods(http.MethodPost)
	r.HandleFunc("/upload/{merkle}/status", s.handleUploadStatus).Methods(http.MethodGet)
	r.HandleFunc("/upload/{merkle}", s.handleUpload).Methods(http.MethodPost)
	r.HandleFunc("/download/{merkle}", s.handleDownload).Methods(http.MethodGet)

	// Internal endpoints (coordinator-only; restrict at network level in prod)
	r.HandleFunc("/challenge", s.handleChallenge).Methods(http.MethodPost)
	r.HandleFunc("/replica-commitment/{merkle}", s.handleReplicaCommitment).Methods(http.MethodPost)
	r.HandleFunc("/replicate", s.handleReplicate).Methods(http.MethodPost)
	r.HandleFunc("/objects/{merkle}", s.handleDeleteObject).Methods(http.MethodDelete)
	r.HandleFunc("/list", s.handleList).Methods(http.MethodGet)

	r.HandleFunc("/health", s.handleHealth).Methods(http.MethodGet)

	// Admin endpoints (local diagnostics)
	r.HandleFunc("/admin/scrub", s.handleScrub).Methods(http.MethodGet, http.MethodPost)

	handler := cors.New(cors.Options{
		AllowedOrigins: []string{}, // no browser clients; machine-to-machine only
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "HEAD"},
		AllowedHeaders: []string{"Authorization", "Content-Type"},
	}).Handler(r)

	s.srv = &http.Server{
		Handler:      handler,
		Addr:         fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port),
		ReadTimeout:  time.Duration(s.cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Info().Str("addr", s.srv.Addr).Msg("provider API listening")
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server: %w", err)
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// bearerToken extracts the token from "Authorization: Bearer <token>".
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || h[:7] != "Bearer " {
		return "", false
	}
	return h[7:], true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
