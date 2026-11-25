package idconsole

import (
	"net/http"
	"testing"
)

func TestTenantAdminApplicationsAndCountsAreFiltered(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "acme-adm", "acme-pass")

	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/applications", token, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	apps := payload["applications"].([]any)
	if len(apps) != 2 {
		t.Fatalf("application count = %d, want 2", len(apps))
	}
	// Per-application counts must only include tenant-a users: 1, 1 and never
	// the two tenant-b users on app-3.
	seen := map[string]int{}
	for _, item := range apps {
		app := item.(map[string]any)
		if app["tenant_id"] != "tenant-a" {
			t.Fatalf("foreign application leaked: %v", app)
		}
		seen[app["id"].(string)] = int(app["user_count"].(float64))
	}
	if seen["app-1"] != 1 || seen["app-2"] != 1 {
		t.Fatalf("per-application counts = %v, want app-1:1 app-2:1", seen)
	}
	if _, leaked := seen["app-3"]; leaked {
		t.Fatalf("foreign app-3 appeared in tenant-a list: %v", seen)
	}
	if got := intField(t, payload, "user_count"); got != 3 {
		t.Fatalf("total user count = %d, want 3 (tenant-a only)", got)
	}
}

func TestTenantAdminUsersAndTenantsAreFiltered(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "glob-adm", "glob-pass")

	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/users", token, nil)
	if status != http.StatusOK {
		t.Fatalf("users status = %d", status)
	}
	users := payload["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("user count = %d, want 2", len(users))
	}
	for _, item := range users {
		if item.(map[string]any)["tenant_id"] != "tenant-b" {
			t.Fatalf("foreign user leaked: %v", item)
		}
	}

	status, payload = doJSON(t, http.MethodGet, server.URL+"/api/tenants", token, nil)
	if status != http.StatusOK {
		t.Fatalf("tenants status = %d", status)
	}
	tenants := payload["tenants"].([]any)
	if len(tenants) != 1 {
		t.Fatalf("tenant count = %d, want 1", len(tenants))
	}
	only := tenants[0].(map[string]any)
	if only["id"] != "tenant-b" || int(only["user_count"].(float64)) != 2 {
		t.Fatalf("tenant view = %v, want tenant-b with 2 users", only)
	}
}

func TestTenantAdminCannotWriteToForeignTenant(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "acme-adm", "acme-pass")

	// Explicit foreign tenant id on the request body must be rejected.
	status, _ := doJSON(t, http.MethodPost, server.URL+"/api/applications", token,
		stringReader(`{"tenant_id":"tenant-b","name":"Sneaky App"}`))
	if status != http.StatusForbidden {
		t.Fatalf("cross-tenant create status = %d, want 403", status)
	}

	// The rejected row must not exist anywhere in the store.
	_, superToken := login(t, server.URL, "root", "root-pass")
	_, payload := doJSON(t, http.MethodGet, server.URL+"/api/applications", superToken, nil)
	for _, item := range payload["applications"].([]any) {
		if item.(map[string]any)["name"] == "Sneaky App" {
			t.Fatalf("forbidden application was persisted: %v", item)
		}
	}

	// Creating inside the home tenant remains allowed.
	status, payload = doJSON(t, http.MethodPost, server.URL+"/api/applications", token,
		stringReader(`{"name":"Acme New App"}`))
	if status != http.StatusCreated {
		t.Fatalf("in-tenant create status = %d, want 201", status)
	}
	if stringField(t, payload, "tenant_id") != "tenant-a" {
		t.Fatalf("new app tenant = %v, want tenant-a", payload["tenant_id"])
	}
}

func TestSuperAdminCrossTenantOperations(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "root", "root-pass")

	// Super admin scoped to tenant-b can create an application in tenant-b only.
	if status, _ := doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":"tenant-b"}`)); status != http.StatusOK {
		t.Fatalf("switch failed: %d", status)
	}
	status, payload := doJSON(t, http.MethodPost, server.URL+"/api/applications", token,
		stringReader(`{"name":"Globex New App"}`))
	if status != http.StatusCreated {
		t.Fatalf("scoped create status = %d, want 201", status)
	}
	if stringField(t, payload, "tenant_id") != "tenant-b" {
		t.Fatalf("tenant_id = %v, want tenant-b", payload["tenant_id"])
	}

	// While pinned to tenant-b, creating for tenant-a is outside the scope.
	status, _ = doJSON(t, http.MethodPost, server.URL+"/api/applications", token,
		stringReader(`{"tenant_id":"tenant-a","name":"Wrong Tenant"}`))
	if status != http.StatusForbidden {
		t.Fatalf("out-of-scope create status = %d, want 403", status)
	}

	// Back to the global view, cross-tenant creation in any tenant works.
	if _, _ = doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":""}`)); true {
	}
	status, payload = doJSON(t, http.MethodPost, server.URL+"/api/applications", token,
		stringReader(`{"tenant_id":"tenant-a","name":"Global Created"}`))
	if status != http.StatusCreated {
		t.Fatalf("global create status = %d, want 201", status)
	}
	if stringField(t, payload, "tenant_id") != "tenant-a" {
		t.Fatalf("tenant_id = %v, want tenant-a", payload["tenant_id"])
	}
}
