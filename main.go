// Command previewtoken runs the team file-sharing preview service.
//
// It issues one-time preview tokens bound to file, version, user, purpose
// and expiry, persists consumed-token state in a JSON file via os and
// encoding/json, and serves the net/http JSON API plus a demo page.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"previewtoken/server"
	"previewtoken/token"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	defaultAddr := envOr("PREVIEW_ADDR", "")
	if defaultAddr == "" {
		if port := os.Getenv("PORT"); port != "" {
			defaultAddr = ":" + port
		} else {
			defaultAddr = ":8080"
		}
	}
	addr := flag.String("addr", defaultAddr, "listen address (host:port)")
	port := flag.String("port", "", "TCP port override (e.g. 8090)")
	dataFile := flag.String("data", envOr("PREVIEW_DATA", filepath.Join("data", "tokens.json")), "JSON ledger path")
	contentDir := flag.String("content", envOr("CONTENT_DIR", filepath.Join("data", "content")), "preview content root")
	secret := flag.String("secret", os.Getenv("PREVIEW_TOKEN_SECRET"), "HMAC secret (or PREVIEW_TOKEN_SECRET); >=16 chars")
	seed := flag.Bool("seed-demo", true, "seed a small demo preview file")
	flag.Parse()

	listenAddr := *addr
	if *port != "" {
		listenAddr = ":" + *port
	}

	var secretBytes []byte
	if *secret != "" {
		if len(*secret) < 16 {
			log.Fatal("PREVIEW_TOKEN_SECRET / -secret must be at least 16 characters")
		}
		secretBytes = []byte(*secret)
	} else {
		generated, err := token.NewEphemeralSecret()
		if err != nil {
			log.Fatalf("generate secret: %v", err)
		}
		secretBytes = generated
		log.Printf("WARNING: using ephemeral HMAC secret; previously issued tokens break after restart. Set PREVIEW_TOKEN_SECRET for stable deployments.")
	}

	store := token.NewJSONStore(*dataFile)
	mgr, err := token.NewManager(secretBytes, store)
	if err != nil {
		log.Fatalf("token manager: %v", err)
	}

	if *seed {
		if err := seedDemoContent(*contentDir); err != nil {
			log.Printf("seed demo content failed: %v", err)
		}
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           server.New(mgr, server.WithContentDir(*contentDir)).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		host := listenAddr
		if len(host) > 0 && host[0] == ':' {
			host = "localhost" + host
		}
		log.Printf("preview token service listening on http://%s  (demo page: /)", host)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown: %v", err)
	}
}

// seedDemoContent writes one small text preview so /preview can return real
// bytes out of the box. Layout matches server content resolution:
// <contentDir>/<file>/versions/<version>.
func seedDemoContent(root string) error {
	demoPath := filepath.Join(root, "welcome.txt", "versions", "v1")
	if _, err := os.Stat(demoPath); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(demoPath), 0o755); err != nil {
		return err
	}
	content := "Team Files — one-time preview token demo\n" +
		"This file is bound to welcome.txt @ v1 for user demo.\n" +
		"The token that fetched it is now consumed; replaying it is rejected.\n"
	return os.WriteFile(demoPath, []byte(content), 0o644)
}
