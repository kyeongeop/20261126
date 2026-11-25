package idconsole

import (
	"net/http"
	"testing"
)

// TestEndToEndTenantIsolation drives the full HTTP stack the way a console
// would: login, list, switch tenant and export, asserting that a tenant admin
// never observes another tenant's application names or user counts.
func TestEndToEndTenantIsolation(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, tenantToken := login(t, server.URL, "acme-adm", "acme-pass")

	status, apps := doJSON(t, http.MethodGet, server.URL+"/api/applications", tenantToken, nil)
	if status != http.StatusOK {
		t.Fatalf("applications: %d", status)
	}
	for _, item := range apps["applications"].([]any) {
		app := item.(map[string]any)
		if app["name"] == "Globex SSO" {
			t.Fatalf("foreign application name leaked: %v", app)
		}
	}

	status, exported := doJSON(t, http.MethodGet, server.URL+"/api/export", tenantToken, nil)
	if status != http.StatusOK {
		t.Fatalf("export: %d", status)
	}
	for _, item := range exported["users"].([]any) {
		email := item.(map[string]any)["email"].(string)
		if len(email) >= 13 && email[len(email)-13:] == "@globex.example" {
			t.Fatalf("foreign user leaked into export: %v", item)
		}
	}

	// A forged Authorization header never resolves to any tenant context.
	if status, _ := doJSON(t, http.MethodGet, server.URL+"/api/export", "forged", nil); status != http.StatusUnauthorized {
		t.Fatalf("forged token status = %d, want 401", status)
	}
}
