package idconsole

import "net/http"

// exportPayload is the on-disk shape of an export. Every collection is
// produced by the same scope-filtered store methods as the API lists, so a
// tenant-scoped export can never contain another tenant's rows.
type exportPayload struct {
	Scope        string         `json:"scope"`
	TenantID     string         `json:"tenant_id,omitempty"`
	Tenants      []*Tenant      `json:"tenants"`
	Applications []*Application `json:"applications"`
	Users        []*User        `json:"users"`
	UserCount    int            `json:"user_count"`
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, scope Scope) {
	label := "tenant"
	if scope.AllTenants() {
		label = "all_tenants"
	}
	payload := exportPayload{
		Scope:        label,
		TenantID:     scope.TenantID,
		Tenants:      s.store.Tenants(scope),
		Applications: s.store.Applications(scope),
		Users:        s.store.Users(scope),
		UserCount:    s.store.UserCount(scope),
	}
	// Force a download so browsers treat the filtered snapshot as an export.
	w.Header().Set("Content-Disposition", `attachment; filename="identity_export.json"`)
	writeJSON(w, http.StatusOK, payload)
}

// applicationID keeps id generation local to the export-free import surface
// while remaining deterministic for tests.
func applicationID(n int) string {
	digits := []byte{}
	if n == 0 {
		digits = append(digits, '0')
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return "app-" + string(digits)
}
