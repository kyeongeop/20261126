// Command fileserver runs the team file sharing HTTP service.
//
// All state is kept in local JSON files under the data directory: share
// records (including salted password hashes) and the anti-guessing throttle
// state. Nothing is stored outside the repository-local data directory and
// no external services are required.
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
	"strconv"
	"syscall"
	"time"

	"fileshare/internal/httpapi"
	"fileshare/internal/ratelimit"
	"fileshare/internal/shares"
	"fileshare/internal/store"
)

func main() {
	var (
		addr        = flag.String("addr", envOr("FILESHARE_ADDR", ":8080"), "HTTP listen address")
		dataDir     = flag.String("data-dir", envOr("FILESHARE_DATA_DIR", "data"), "directory for persisted state files")
		trustProxy  = flag.Bool("trust-proxy", envOr("FILESHARE_TRUST_PROXY", "") == "true", "trust X-Forwarded-For (only behind a trusted proxy)")
		pbkdf2Iters = flag.Int("pbkdf2-iterations", envIntOr("FILESHARE_PBKDF2_ITERATIONS", 600_000), "PBKDF2 iterations for password hashing")
		window      = flag.Duration("window", envDurOr("FILESHARE_WINDOW", 10*time.Minute), "attempt counting window")
		maxAttempts = flag.Int("max-attempts", envIntOr("FILESHARE_MAX_ATTEMPTS", 5), "max attempts per window and source")
		maxFails    = flag.Int("max-consecutive-failures", envIntOr("FILESHARE_MAX_FAILURES", 5), "consecutive failures that trigger a lock")
		lockout     = flag.Duration("lockout", envDurOr("FILESHARE_LOCKOUT", 5*time.Minute), "lock duration after limits are breached")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "fileshare ", log.LstdFlags|log.Lmsgprefix)

	sharesPath := filepath.Join(*dataDir, "shares.json")
	ratePath := filepath.Join(*dataDir, "attempts.json")

	sharesMgr, err := shares.NewManager(sharesPath, *pbkdf2Iters)
	if err != nil {
		logger.Fatalf("init share store: %v", err)
	}
	rateStore, err := store.Open[ratelimit.State](ratePath)
	if err != nil {
		logger.Fatalf("init attempt store: %v", err)
	}

	cfg := ratelimit.Config{
		MaxAttemptsPerWindow:   *maxAttempts,
		Window:                 *window,
		MaxConsecutiveFailures: *maxFails,
		Lockout:                *lockout,
	}
	svc := httpapi.NewService(sharesMgr, rateStore, cfg, *trustProxy, logger)

	server := &http.Server{
		Addr:              *addr,
		Handler:           svc.NewMux(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go runSweeper(ctx, svc, time.Minute, logger)

	go func() {
		logger.Printf("listening on %s (data dir: %s)", *addr, *dataDir)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	logger.Printf("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Printf("graceful shutdown failed: %v", err)
	}
	if err := svc.SweepExpired(); err != nil {
		logger.Printf("final sweep failed: %v", err)
	}
	logger.Printf("stopped")
}

func runSweeper(ctx context.Context, svc *httpapi.Service, interval time.Duration, logger *log.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := svc.SweepExpired(); err != nil {
				logger.Printf("sweep failed: %v", err)
			}
		}
	}
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envDurOr(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
