package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"namespaceguard/namespace"
)

func main() {
	statePath := envOr("NAMESPACE_STATE", "data/state.json")
	fixturePath := envOr("NAMESPACE_FIXTURE", "fixtures/seed.json")
	store, err := namespace.OpenStore(statePath, fixturePath)
	if err != nil {
		log.Fatalf("load namespace store: %v", err)
	}
	service := namespace.NewService(store, nil)
	handler := namespace.NewHandler(service)

	addr := envOr("ADDR", "")
	if addr == "" {
		port := envOr("PORT", "8080")
		addr = "127.0.0.1:" + strings.TrimPrefix(port, ":")
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("namespace ownership service listening on %s (state=%s fixture=%s)", addr, statePath, fixturePath)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
