package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	defaultAddr := firstNonEmpty(
		os.Getenv("PKG_ADDR"),
		os.Getenv("ADDR"),
		envPortAddr(os.Getenv("PORT")),
		"127.0.0.1:8080",
	)
	addr := flag.String("addr", defaultAddr, "HTTP listen address")
	dataDir := flag.String("data", firstNonEmpty(os.Getenv("PKG_DATA_DIR"), os.Getenv("DATA_DIR"), "./data"), "data directory")
	cooldownFlag := flag.Duration("cooldown", defaultCooldown(), "deletion cooldown duration (e.g. 24h, 10m, 30s, 0s)")
	portFlag := flag.String("port", "", "TCP port (overrides the port portion of -addr)")
	flag.StringVar(dataDir, "dir", *dataDir, "alias of -data")
	flag.StringVar(dataDir, "data-dir", *dataDir, "alias of -data")
	flag.StringVar(dataDir, "store", *dataDir, "alias of -data")
	flag.StringVar(dataDir, "storage", *dataDir, "alias of -data")
	addrFlag := flag.String("address", "", "alias of -addr")
	flag.Parse()

	if *addrFlag != "" {
		*addr = *addrFlag
	}
	if p := strings.TrimSpace(*portFlag); p != "" {
		if _, err := strconv.Atoi(p); err == nil {
			*addr = ":" + p
		} else {
			*addr = p
		}
	}

	cooldown := *cooldownFlag
	if raw := firstNonEmpty(os.Getenv("PKG_DELETION_COOLDOWN"), os.Getenv("DELETION_COOLDOWN"),
		os.Getenv("PKG_COOLDOWN"), os.Getenv("COOLDOWN")); raw != "" && !flagPassed("cooldown") {
		if d, err := parseCooldown(raw); err == nil {
			cooldown = d
		} else {
			log.Printf("ignore invalid cooldown %q: %v", raw, err)
		}
	}
	if raw := firstNonEmpty(os.Getenv("PKG_DELETION_COOLDOWN_SECONDS"), os.Getenv("COOLDOWN_SECONDS"),
		os.Getenv("PKG_COOLDOWN_SECONDS")); raw != "" && !flagPassed("cooldown") {
		if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
			cooldown = time.Duration(secs) * time.Second
		}
	}

	store, err := NewStore(*dataDir, cooldown)
	if err != nil {
		log.Fatalf("initialize store: %v", err)
	}
	if seedSpec := os.Getenv("PKG_SEED_DEMO"); seedSpec == "" || truthy(seedSpec) {
		store.SeedDemoDataIfEmpty()
	}
	app := NewApp(store, newAuthConfig())

	server := &http.Server{
		Addr:              *addr,
		Handler:           app,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	log.Printf("package repository with deletion cooldown listening on http://%s (data=%s, cooldown=%s)",
		*addr, *dataDir, cooldown)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func defaultCooldown() time.Duration {
	raw := firstNonEmpty(os.Getenv("PKG_DELETION_COOLDOWN"), os.Getenv("DELETION_COOLDOWN"),
		os.Getenv("PKG_COOLDOWN"), os.Getenv("COOLDOWN"))
	if raw != "" {
		if d, err := parseCooldown(raw); err == nil {
			return d
		}
	}
	if raw := firstNonEmpty(os.Getenv("PKG_DELETION_COOLDOWN_SECONDS"), os.Getenv("COOLDOWN_SECONDS"),
		os.Getenv("PKG_COOLDOWN_SECONDS")); raw != "" {
		if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return 24 * time.Hour
}

// parseCooldown 同时接受 Go duration（"90s"、"24h"）和纯数字秒（"90"）。
func parseCooldown(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Duration(secs) * time.Second, nil
	}
	return time.ParseDuration(raw)
}

func envPortAddr(port string) string {
	if port == "" {
		return ""
	}
	if _, err := strconv.Atoi(port); err == nil {
		return ":" + port
	}
	return port
}

func flagPassed(name string) bool {
	passed := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			passed = true
		}
	})
	return passed
}
