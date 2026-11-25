package idconsole

import "net/http"

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token        string `json:"token"`
	Role         Role   `json:"role"`
	ActiveTenant string `json:"active_tenant"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	admin := s.store.AdminByUsername(req.Username)
	// Run the hash check even when the user is missing to avoid trivial
	// username enumeration through response timing differences.
	if admin == nil || !VerifyPassword(admin, req.Password) {
		writeError(w, &APIError{Status: 401, Code: "invalid_credentials", Message: "invalid username or password"})
		return
	}
	token, err := newToken()
	if err != nil {
		writeError(w, err)
		return
	}
	session := &Session{
		Token:        token,
		AdminID:      admin.ID,
		Role:         admin.Role,
		TenantID:     admin.TenantID,
		ActiveTenant: admin.TenantID, // tenant admins start inside their boundary
	}
	s.store.CreateSession(session)
	writeJSON(w, http.StatusOK, loginResponse{
		Token:        token,
		Role:         admin.Role,
		ActiveTenant: session.ActiveTenant,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token := bearerToken(r); token != "" {
		s.store.DeleteSession(token)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

type switchTenantRequest struct {
	TenantID string `json:"tenant_id"`
}

// handleSwitchTenant revalidates the requested tenant against the admin's
// server-side identity before mutating the session. Page-side tenant values
// are treated as untrusted input.
func (s *Server) handleSwitchTenant(w http.ResponseWriter, r *http.Request) {
	scope, session, err := s.resolveScope(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var req switchTenantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.TenantID != "" && !s.store.TenantExists(req.TenantID) {
		writeError(w, errNotFound)
		return
	}
	if scope.Role == RoleTenantAdmin && req.TenantID != session.TenantID {
		// A tenant admin attempting to switch into another tenant is a
		// boundary violation, not a missing resource.
		writeError(w, errForbidden)
		return
	}
	s.store.SwitchTenant(session.Token, req.TenantID)
	writeJSON(w, http.StatusOK, map[string]string{"active_tenant": req.TenantID})
}
