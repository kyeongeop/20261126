package idconsole

import "net/http"

type tenantView struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UserCount int    `json:"user_count"`
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request, scope Scope) {
	tenants := s.store.Tenants(scope)
	views := make([]tenantView, 0, len(tenants))
	for _, t := range tenants {
		// Count through a per-tenant scope so no foreign users are tallied.
		tenantScope := Scope{Role: RoleTenantAdmin, TenantID: t.ID}
		views = append(views, tenantView{
			ID:        t.ID,
			Name:      t.Name,
			UserCount: s.store.UserCount(tenantScope),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenants":    views,
		"user_count": s.store.UserCount(scope),
	})
}

type applicationView struct {
	ID        string `json:"id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	UserCount int    `json:"user_count"`
}

func (s *Server) handleListApplications(w http.ResponseWriter, r *http.Request, scope Scope) {
	apps := s.store.Applications(scope)
	// One scope-filtered aggregate: foreign applications are absent and
	// foreign users can never inflate the per-application counts.
	counts := s.store.UserCountByApplication(scope)
	views := make([]applicationView, 0, len(apps))
	for _, a := range apps {
		views = append(views, applicationView{
			ID:        a.ID,
			TenantID:  a.TenantID,
			Name:      a.Name,
			UserCount: counts[a.ID],
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"applications": views,
		"user_count":   s.store.UserCount(scope),
	})
}

type createApplicationRequest struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
}

func (s *Server) handleCreateApplication(w http.ResponseWriter, r *http.Request, scope Scope) {
	var req createApplicationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Name == "" {
		writeError(w, errBadRequest)
		return
	}
	targetTenant := req.TenantID
	if targetTenant == "" {
		targetTenant = scope.TenantID
	}
	if targetTenant == "" {
		// A super admin without an active tenant must name the target tenant.
		writeError(w, errBadRequest)
		return
	}
	if !scope.Visible(targetTenant) {
		// Tenant admins writing into another tenant are rejected outright;
		// do not reveal whether the foreign tenant exists.
		writeError(w, errForbidden)
		return
	}
	if !s.store.TenantExists(targetTenant) {
		writeError(w, errNotFound)
		return
	}
	app := &Application{
		ID:       s.store.NextApplicationID(),
		TenantID: targetTenant,
		Name:     req.Name,
	}
	s.store.AddApplication(app)
	writeJSON(w, http.StatusCreated, app)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, scope Scope) {
	users := s.store.Users(scope)
	writeJSON(w, http.StatusOK, map[string]any{
		"users":      users,
		"user_count": len(users),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request, scope Scope) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_count":      len(s.store.Tenants(scope)),
		"application_count": len(s.store.Applications(scope)),
		"user_count":        s.store.UserCount(scope),
	})
}
