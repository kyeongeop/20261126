// Command fileshare runs the team file-sharing HTTP service with the
// emergency directory freeze capability.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"fileshare/internal/server"
)

func main() {
	addr := flag.String("addr", envOr("FILESHARE_ADDR", ":8080"), "HTTP listen address")
	shareDir := flag.String("share-dir", envOr("FILESHARE_SHARE_DIR", "./data/share"), "shared files directory")
	stateDir := flag.String("state-dir", envOr("FILESHARE_STATE_DIR", "./data/state"), "freeze state and audit directory")
	flag.Parse()

	srv, err := server.New(*shareDir, *stateDir)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	log.Printf("fileshare listening on %s (share=%s, state=%s)", *addr, *shareDir, *stateDir)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
