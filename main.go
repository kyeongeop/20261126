package main

import (
	"flag"
	"log"
	"net/http"

	"teamsync/internal/server"
	"teamsync/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dataDir := flag.String("data", "./data", "directory for the JSON state file")
	flag.Parse()

	st, err := store.NewStore(*dataDir)
	if err != nil {
		log.Fatalf("store init failed: %v", err)
	}
	handler := server.New(st)

	log.Printf("TeamSync listening on %s (state: %s)", *addr, *dataDir)
	if err := http.ListenAndServe(*addr, handler); err != nil {
		log.Fatal(err)
	}
}
