package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"guestshare/internal/guest"
)

func main() {
	addr := envOrDefault("ADDR", ":8080")
	shareRoot := envOrDefault("SHARE_ROOT", "./fixtures/team")
	dataFile := envOrDefault("DATA_FILE", "./data/state.json")
	inviterName := envOrDefault("INVITER_NAME", "team")
	adminToken := os.Getenv("INVITER_TOKEN")
	if adminToken == "" {
		log.Fatal("INVITER_TOKEN is required")
	}
	secureCookies, err := strconv.ParseBool(envOrDefault("SECURE_COOKIES", "false"))
	if err != nil {
		log.Fatalf("invalid SECURE_COOKIES: %v", err)
	}

	service, err := guest.NewService(guest.Config{
		Root:     shareRoot,
		DataFile: dataFile,
	})
	if err != nil {
		log.Fatalf("initialize guest service: %v", err)
	}
	handler, err := guest.NewHandler(service, guest.HTTPConfig{
		AdminToken:    adminToken,
		InviterName:   inviterName,
		SecureCookies: secureCookies,
	})
	if err != nil {
		log.Fatalf("initialize HTTP handler: %v", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownSignal.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
	}()

	log.Printf("guestshare listening on %s with share root %s", addr, shareRoot)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
