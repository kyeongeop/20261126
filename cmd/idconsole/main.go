// Command idconsole starts the enterprise identity management console with
// the approval-based MFA reset workflow exposed over HTTP. It uses only the
// Go standard library and in-memory state, so it needs no external database.
package main

import (
	"log"
	"net/http"
	"os"

	"idconsole/mfa"
)

func main() {
	store := mfa.NewMemoryStore()
	seed(store)

	service := mfa.NewService(store, mfa.NewRecordingNotifier(), nil)
	handler := mfa.NewHandler(service)

	addr := os.Getenv("IDCONSOLE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	log.Printf("identity console listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

func seed(store *mfa.MemoryStore) {
	store.CreateUser(mfa.User{
		ID: "u-alice", Name: "Alice", Role: mfa.RoleUser,
		Email: "alice@example.com", Phone: "+10000000001",
		MFAEnrolled: true, MFASecret: "seed-secret",
	})
	store.CreateApp(mfa.App{ID: "app-wiki", Name: "Wiki", HighSensitive: false})
	store.CreateApp(mfa.App{ID: "app-payroll", Name: "Payroll", HighSensitive: true})
}
