package main

import (
	_ "embed"
	"net/http"
)

//go:embed web/index.html
var indexHTML []byte

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(indexHTML)
}
