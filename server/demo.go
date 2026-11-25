package server

import (
	_ "embed"
	"net/http"
)

//go:embed demo.html
var demoHTML []byte

// handleDemo serves a self-contained page that exercises single-use tokens
// and same-page thumbnail batches.
func (s *Server) handleDemo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(demoHTML)
}
