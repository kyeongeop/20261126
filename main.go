// Command fileshare runs the team file-sharing service with the file
// access timeline feature. It depends only on the Go standard library and
// persists events to a local append-only log.
package main

import (
	"flag"
	"log"
	"net/http"

	"fileshare/internal/httpapi"
	"fileshare/internal/timeline"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dataDir := flag.String("data", "./data", "directory for the timeline log")
	flag.Parse()

	store, err := timeline.Open(*dataDir)
	if err != nil {
		log.Fatalf("open timeline store: %v", err)
	}
	defer store.Close()

	server := httpapi.NewServer(store)
	log.Printf("fileshare listening on %s (data dir %s)", *addr, *dataDir)
	if err := http.ListenAndServe(*addr, server.Handler()); err != nil {
		log.Fatalf("http server: %v", err)
	}
}
