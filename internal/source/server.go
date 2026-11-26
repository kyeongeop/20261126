package source

import (
	"log"
	"net/http"
	"os"
)

// NewFileHandler serves an image directory over HTTP. The standard library
// FileServer implements HEAD and Range requests, which is exactly what
// HTTPSource needs for integrity checks and resumable downloads.
func NewFileHandler(imageRoot string) (http.Handler, error) {
	if _, err := os.Stat(imageRoot); err != nil {
		return nil, err
	}
	return http.FileServer(http.Dir(imageRoot)), nil
}

// ListenAndServe exposes imageRoot on addr until the server fails.
func ListenAndServe(addr, imageRoot string) error {
	handler, err := NewFileHandler(imageRoot)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/", handler)
	log.Printf("serving image %s on http://%s/", imageRoot, addr)
	return http.ListenAndServe(addr, mux)
}
