// Command registry runs the internal package registry server.
// All state lives under the data directory inside the repository;
// no external services are required.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"pkgregistry/internal/audit"
	"pkgregistry/internal/server"
	"pkgregistry/internal/store"
	"pkgregistry/internal/token"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	dataDir := flag.String("data", "data", "data directory (tokens, packages, audit log)")
	flag.Parse()

	adminToken := os.Getenv("REGISTRY_ADMIN_TOKEN")
	if adminToken == "" {
		log.Fatal("REGISTRY_ADMIN_TOKEN must be set (gates /v1/admin/* endpoints)")
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	tokens, err := token.OpenStore(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	pkgs, err := store.Open(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	auditLog, err := audit.Open(filepath.Join(*dataDir, "audit.log"))
	if err != nil {
		log.Fatal(err)
	}
	defer auditLog.Close()

	srv := server.New(tokens, pkgs, auditLog, adminToken)
	log.Printf("registry listening on %s, data in %s", *addr, *dataDir)
	log.Fatal(http.ListenAndServe(*addr, srv))
}
