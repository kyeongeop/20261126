// Command fileshare runs the versioned, encrypted team file sharing server.
// All data (keyring, manifests, ciphertext blobs) stays on the local disk.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"fileshare/internal/keyring"
	"fileshare/internal/server"
	"fileshare/internal/store"
)

func main() {
	addr := flag.String("addr", envOr("ADDR", ":8080"), "listen address")
	dataDir := flag.String("data", envOr("DATA_DIR", "./data"), "data directory")
	creator := flag.String("bootstrap-creator",
		envOr("BOOTSTRAP_CREATOR", "system"), "creator recorded for the initial KEK")
	flag.Parse()

	kr, err := keyring.Open(*dataDir+"/keyring", *creator)
	if err != nil {
		log.Fatalf("open keyring: %v", err)
	}
	st := store.New(*dataDir, kr)

	srv := server.New(st, kr)
	log.Printf("fileshare listening on %s, data dir %s, active KEK v%d",
		*addr, *dataDir, kr.ActiveVersion())
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
