package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed web
var webFS embed.FS

func (s *Server) handleEditor(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Path != "/" {
		// Only real embedded assets are served; unknown paths stay 404.
		if _, err := fs.Stat(sub, strings.TrimPrefix(r.URL.Path, "/")); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	http.FileServer(http.FS(sub)).ServeHTTP(w, r)
}
