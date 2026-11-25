package idconsole

import (
	"net/http"
	"testing"
)

func TestLoginRejectsBadCredentials(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	status, _ := login(t, server.URL, "acme-adm", "wrong-password")
	if status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}
}

func TestEndpointsRequireAuthentication(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	for _, path := range []string{"/api/tenants", "/api/applications", "/api/users", "/api/stats", "/api/export"} {
		status, _ := doJSON(t, http.MethodGet, server.URL+path, "", nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("GET %s status = %d, want 401", path, status)
		}
	}

	status, _ := doJSON(t, http.MethodGet, server.URL+"/api/applications", "Bearer tampered-token", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("forged token status = %d, want 401", status)
	}
}

func TestTenantAdminCannotSwitchToForeignTenant(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "acme-adm", "acme-pass")
	status, _ := doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":"tenant-b"}`))
	if status != http.StatusForbidden {
		t.Fatalf("switch status = %d, want 403", status)
	}

	// The rejected switch must not change the active tenant context.
	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/tenants", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list tenants status = %d", status)
	}
	tenants := payload["tenants"].([]any)
	if len(tenants) != 1 {
		t.Fatalf("tenant count = %d, want 1", len(tenants))
	}
	only := tenants[0].(map[string]any)
	if only["id"] != "tenant-a" {
		t.Fatalf("visible tenant = %v, want tenant-a", only["id"])
	}
}

func TestTenantContextIsRevalidatedFromSession(t *testing.T) {
	server, store := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "acme-adm", "acme-pass")

	// Simulate stale page state: force a foreign active tenant into the
	// session record. Scope resolution must still pin the admin to tenant-a.
	store.SwitchTenant(token, "tenant-b")

	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/applications", token, nil)
	if status != http.StatusOK {
		t.Fatalf("list status = %d", status)
	}
	apps := payload["applications"].([]any)
	if len(apps) != 2 {
		t.Fatalf("application count = %d, want 2", len(apps))
	}
	for _, item := range apps {
		app := item.(map[string]any)
		if app["tenant_id"] != "tenant-a" {
			t.Fatalf("leaked foreign application %v", app)
		}
	}
}

func TestSuperAdminSwitchesTenantsAndBack(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "root", "root-pass")

	// Initially the super admin spans every tenant.
	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/stats", token, nil)
	if status != http.StatusOK {
		t.Fatalf("stats status = %d", status)
	}
	if got := intField(t, payload, "user_count"); got != 5 {
		t.Fatalf("global user count = %d, want 5", got)
	}

	// Switch into tenant-b: the same session is now bounded to that tenant.
	status, _ = doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":"tenant-b"}`))
	if status != http.StatusOK {
		t.Fatalf("switch status = %d, want 200", status)
	}
	status, payload = doJSON(t, http.MethodGet, server.URL+"/api/stats", token, nil)
	if got := intField(t, payload, "user_count"); got != 2 {
		t.Fatalf("scoped user count = %d, want 2", got)
	}

	// Switching to an unknown tenant is rejected without touching context.
	status, _ = doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":"tenant-ghost"}`))
	if status != http.StatusNotFound {
		t.Fatalf("unknown switch status = %d, want 404", status)
	}

	// Empty tenant id returns the super admin to the cross-tenant view.
	status, _ = doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":""}`))
	if status != http.StatusOK {
		t.Fatalf("reset switch status = %d, want 200", status)
	}
	status, payload = doJSON(t, http.MethodGet, server.URL+"/api/stats", token, nil)
	if got := intField(t, payload, "user_count"); got != 5 {
		t.Fatalf("global user count after reset = %d, want 5", got)
	}
}
