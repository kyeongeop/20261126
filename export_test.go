package idconsole

import (
	"net/http"
	"testing"
)

func TestTenantAdminExportContainsOnlyOwnTenant(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "acme-adm", "acme-pass")

	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/export", token, nil)
	if status != http.StatusOK {
		t.Fatalf("export status = %d", status)
	}
	if stringField(t, payload, "scope") != "tenant" {
		t.Fatalf("scope = %v, want tenant", payload["scope"])
	}
	if stringField(t, payload, "tenant_id") != "tenant-a" {
		t.Fatalf("export tenant_id = %v, want tenant-a", payload["tenant_id"])
	}

	tenants := payload["tenants"].([]any)
	if len(tenants) != 1 || tenants[0].(map[string]any)["id"] != "tenant-a" {
		t.Fatalf("export tenants = %v, want only tenant-a", tenants)
	}
	apps := payload["applications"].([]any)
	if len(apps) != 2 {
		t.Fatalf("export applications = %d, want 2", len(apps))
	}
	users := payload["users"].([]any)
	if len(users) != 3 {
		t.Fatalf("export users = %d, want 3", len(users))
	}
	for _, item := range users {
		if item.(map[string]any)["tenant_id"] != "tenant-a" {
			t.Fatalf("foreign user in export: %v", item)
		}
	}
	if got := intField(t, payload, "user_count"); got != 3 {
		t.Fatalf("export user_count = %d, want 3", got)
	}
}

func TestSuperAdminExportScopesWithActiveTenant(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "root", "root-pass")

	// Global export spans everything.
	status, payload := doJSON(t, http.MethodGet, server.URL+"/api/export", token, nil)
	if status != http.StatusOK {
		t.Fatalf("global export status = %d", status)
	}
	if stringField(t, payload, "scope") != "all_tenants" {
		t.Fatalf("scope = %v, want all_tenants", payload["scope"])
	}
	if got := intField(t, payload, "user_count"); got != 5 {
		t.Fatalf("global export users = %d, want 5", got)
	}

	// After switching, the export is bounded exactly like the list APIs.
	if status, _ := doJSON(t, http.MethodPost, server.URL+"/api/tenant/switch", token,
		stringReader(`{"tenant_id":"tenant-b"}`)); status != http.StatusOK {
		t.Fatalf("switch failed")
	}
	status, payload = doJSON(t, http.MethodGet, server.URL+"/api/export", token, nil)
	if status != http.StatusOK {
		t.Fatalf("scoped export status = %d", status)
	}
	if stringField(t, payload, "scope") != "tenant" || stringField(t, payload, "tenant_id") != "tenant-b" {
		t.Fatalf("scoped export envelope = %v", payload)
	}
	if got := intField(t, payload, "user_count"); got != 2 {
		t.Fatalf("scoped export users = %d, want 2", got)
	}
	for _, item := range payload["applications"].([]any) {
		if item.(map[string]any)["tenant_id"] != "tenant-b" {
			t.Fatalf("foreign application in scoped export: %v", item)
		}
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	server, _ := newTestServer(t)
	defer server.Close()

	_, token := login(t, server.URL, "acme-adm", "acme-pass")
	if status, _ := doJSON(t, http.MethodPost, server.URL+"/api/logout", token, nil); status != http.StatusOK {
		t.Fatalf("logout status = %d", status)
	}
	if status, _ := doJSON(t, http.MethodGet, server.URL+"/api/users", token, nil); status != http.StatusUnauthorized {
		t.Fatalf("post-logout access status = %d, want 401", status)
	}
}

func TestPasswordHashingAndVerification(t *testing.T) {
	admin := &Admin{ID: "admin-x", Username: "x"}
	if err := SetPassword(admin, "secret"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if !VerifyPassword(admin, "secret") {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword(admin, "wrong") {
		t.Fatal("wrong password accepted")
	}

	// The same password must yield different hashes thanks to the random salt.
	other := &Admin{ID: "admin-y", Username: "y"}
	if err := SetPassword(other, "secret"); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if string(admin.PasswordSalt) == string(other.PasswordSalt) {
		t.Fatal("salts were not unique")
	}
	if string(admin.PasswordHash) == string(other.PasswordHash) {
		t.Fatal("hashes collided despite distinct salts")
	}
}

func TestTokenIsRandomHex(t *testing.T) {
	tokenA, err := newToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	tokenB, err := newToken()
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if tokenA == tokenB {
		t.Fatal("tokens were identical")
	}
	if len(tokenA) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(tokenA))
	}
	for _, c := range tokenA {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex character %q in token", c)
		}
	}
}

func TestScopeVisibility(t *testing.T) {
	tenantScope := Scope{Role: RoleTenantAdmin, TenantID: "tenant-a"}
	if !tenantScope.Visible("tenant-a") || tenantScope.Visible("tenant-b") {
		t.Fatal("tenant scope visibility incorrect")
	}
	global := Scope{Role: RoleSuperAdmin}
	if !global.Visible("tenant-a") || !global.Visible("tenant-b") || !global.AllTenants() {
		t.Fatal("super admin scope should span every tenant")
	}
	if tenantScope.AllTenants() {
		t.Fatal("tenant scope reported as global")
	}
}
