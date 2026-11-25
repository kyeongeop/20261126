package main

import (
	"idconsole"
	"net/http"
)

func main() {
	store, _, err := idconsole.SeedData()
	if err != nil {
		panic(err)
	}
	server := idconsole.NewServer(store)
	if err := http.ListenAndServe(":8080", server); err != nil {
		panic(err)
	}
}
