// Package httpapi exposes the file access timeline over net/http with a
// JSON API and a server-rendered file detail page.
package httpapi

import (
	"encoding/json"
	"log"
	"net/http"

	"fileshare/internal/timeline"
)

// Server wires the timeline store to HTTP handlers.
type Server struct {
	store *timeline.Store
	mux   *http.ServeMux
}

// NewServer builds the HTTP application.
func NewServer(store *timeline.Store) *Server {
	s := &Server{store: store, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	s.mux.HandleFunc("GET /api/files", s.handleListFiles)
	s.mux.HandleFunc("GET /api/files/{fileID}", s.handleGetFile)
	s.mux.HandleFunc("GET /api/files/{fileID}/timeline", s.handleTimeline)
	s.mux.HandleFunc("GET /api/files/{fileID}/versions", s.handleVersions)
	s.mux.HandleFunc("POST /api/files/{fileID}/events", s.handleIngest)
	s.mux.HandleFunc("POST /api/events", s.handleBatchIngest)
	s.mux.HandleFunc("GET /api/events/{dedupKey}", s.handleGetEvent)
	s.mux.HandleFunc("DELETE /api/events/{dedupKey}", s.handleDeleteEvent)

	s.mux.HandleFunc("GET /files/{fileID}", s.handleDetailPage)
	s.mux.HandleFunc("GET /", s.handleIndex)
}

// Handler returns the root handler, ready for http.ListenAndServe.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}
