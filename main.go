package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"certgateway/internal/gateway"
	"certgateway/internal/inventory"
)

//go:embed web/*
var webFiles embed.FS

func main() {
	rootFlag := flag.String("root", envOr("GATEWAY_ROOT", "."), "workspace root used to resolve relative fixture paths")
	configFlag := flag.String("config", envOr("GATEWAY_CONFIG", "fixtures/gateway/gateway.json"), "gateway certificate configuration")
	stateFlag := flag.String("state", envOr("GATEWAY_STATE", "fixtures/gateway/state.json"), "gateway in-memory snapshot persisted between process starts")
	addrFlag := flag.String("addr", defaultAddr(), "HTTP listen address")
	flag.Parse()

	root, err := filepath.Abs(*rootFlag)
	if err != nil {
		log.Fatalf("resolve root: %v", err)
	}
	configPath := resolve(root, *configFlag)
	statePath := resolve(root, *stateFlag)

	gatewayState, err := gateway.New(configPath, statePath, root)
	if err != nil {
		log.Fatalf("initialize gateway: %v", err)
	}
	service := inventory.NewService(gatewayState)

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(mustSub(webFiles, "web")))))
	mux.HandleFunc("/certificates", handleCertificatesPage)
	mux.HandleFunc("/api/certificates", handleCertificatesAPI(service))
	mux.HandleFunc("/api/gateway/reload", handleReloadAPI(gatewayState))
	mux.HandleFunc("/healthz", handleHealth)

	handler := withCommonHeaders(withRequestLog(mux))
	server := &http.Server{
		Addr:              *addrFlag,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	listener, err := net.Listen("tcp", *addrFlag)
	if err != nil {
		log.Fatalf("listen on %s: %v", *addrFlag, err)
	}
	log.Printf("certificate inventory listening on http://%s/certificates", listener.Addr())

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/certificates", http.StatusFound)
}

func handleCertificatesPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := webFiles.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "certificate page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func handleCertificatesAPI(service *inventory.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		filter, err := parseFilter(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		response := service.List(filter)
		writeJSON(w, http.StatusOK, response)
	}
}

func handleReloadAPI(gatewayState *gateway.Gateway) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if err := gatewayState.Reload(); err != nil {
			snapshot := gatewayState.Snapshot()
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"error":       err.Error(),
				"reloaded_at": snapshot.ReloadedAt,
			})
			return
		}
		snapshot := gatewayState.Snapshot()
		if len(snapshot.Errors) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{
				"status":       "partial",
				"error":        fmt.Sprintf("%d 张证书未能加载", len(snapshot.Errors)),
				"errors":       snapshot.Errors,
				"reloaded_at":  snapshot.ReloadedAt,
				"certificates": len(snapshot.Certificates),
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"reloaded_at":  snapshot.ReloadedAt,
			"certificates": len(snapshot.Certificates),
		})
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func parseFilter(r *http.Request) (inventory.Filter, error) {
	query := r.URL.Query()
	filter := inventory.Filter{
		Preset:        first(query, "expiry", "expires"),
		ExpiresBefore: first(query, "expires_before", "expiry_to", "to"),
		ExpiresAfter:  first(query, "expires_after", "expiry_from", "from"),
		Usage:         first(query, "usage", "status"),
		Query:         first(query, "q", "query", "search"),
	}
	if filter.Preset == "" {
		filter.Preset = "all"
	}
	switch filter.Preset {
	case "all", "expired", "7d", "30d", "90d", "custom":
	default:
		return filter, fmt.Errorf("unknown expiry filter %q", filter.Preset)
	}
	for label, value := range map[string]string{
		"expires_before": filter.ExpiresBefore,
		"expires_after":  filter.ExpiresAfter,
	} {
		if value == "" {
			continue
		}
		if _, err := time.Parse("2006-01-02", value); err != nil {
			return filter, fmt.Errorf("%s must use YYYY-MM-DD", label)
		}
	}
	if filter.Usage != "" && filter.Usage != "all" {
		switch filter.Usage {
		case inventory.UsageActive, inventory.UsageStale, inventory.UsageStandby, inventory.UsagePending, inventory.UsageUnloaded:
		default:
			return filter, fmt.Errorf("unknown usage status %q", filter.Usage)
		}
	}
	return filter, nil
}

func first(values map[string][]string, keys ...string) string {
	for _, key := range keys {
		items := values[key]
		if len(items) == 0 {
			continue
		}
		if value := strings.TrimSpace(items[0]); value != "" {
			return value
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.RequestURI(), time.Since(started).Round(time.Millisecond))
	})
}

func mustSub(files embed.FS, path string) fs.FS {
	sub, err := fs.Sub(files, path)
	if err != nil {
		panic(err)
	}
	return sub
}

func resolve(root, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(root, path)
}

func defaultAddr() string {
	if value := strings.TrimSpace(os.Getenv("ADDR")); value != "" {
		return value
	}
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return "127.0.0.1:8080"
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
