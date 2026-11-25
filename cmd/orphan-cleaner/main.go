package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kyeongeop/20261126/cleanup"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dataPath := flag.String("data", "data/store.json", "path to the JSON dataset")
	filesRoot := flag.String("files", ".", "root directory used to resolve relative resource paths")
	manifestDir := flag.String("manifests", "manifests", "directory for generated JSON change manifests")
	flag.Parse()

	absoluteData, err := filepath.Abs(*dataPath)
	if err != nil {
		return fmt.Errorf("resolve data path: %w", err)
	}
	absoluteFiles, err := filepath.Abs(*filesRoot)
	if err != nil {
		return fmt.Errorf("resolve files root: %w", err)
	}
	absoluteManifests, err := filepath.Abs(*manifestDir)
	if err != nil {
		return fmt.Errorf("resolve manifest directory: %w", err)
	}

	service, err := cleanup.NewService(cleanup.Config{
		StorePath:   absoluteData,
		ManifestDir: absoluteManifests,
		FilesRoot:   absoluteFiles,
	})
	if err != nil {
		return fmt.Errorf("open cleanup service: %w", err)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           logRequests(cleanup.NewHandler(service)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("orphan permission cleanup listening on %s; data=%s files=%s manifests=%s",
		*addr, absoluteData, absoluteFiles, absoluteManifests)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(started))
	})
}
