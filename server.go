package idconsole

import (
	"encoding/json"
	"net/http"
)

// Server wires the store to the HTTP routes.
type Server struct {
	store *Store
	mux   *http.ServeMux
}

// NewServer builds a server with the console API registered.
func NewServer(store *Store) *Server {
	s := &Server{store: store, mux: http.NewServeMux()}
	s.routes()
	return s
}

// ServeHTTP makes the server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/tenant/switch", s.handleSwitchTenant)
	s.mux.HandleFunc("GET /api/tenants", s.withScope(s.handleListTenants))
	s.mux.HandleFunc("GET /api/applications", s.withScope(s.handleListApplications))
	s.mux.HandleFunc("POST /api/applications", s.withScope(s.handleCreateApplication))
	s.mux.HandleFunc("GET /api/users", s.withScope(s.handleListUsers))
	s.mux.HandleFunc("GET /api/stats", s.withScope(s.handleStats))
	s.mux.HandleFunc("GET /api/export", s.withScope(s.handleExport))
}

// writeJSON encodes a response with the given HTTP status.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError renders an APIError or falls back to a generic 500.
func writeError(w http.ResponseWriter, err error) {
	if apiErr, ok := err.(*APIError); ok {
		writeJSON(w, apiErr.Status, apiErr)
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"code":    "internal_error",
		"message": "internal server error",
	})
}

// decodeJSON reads a bounded JSON request body into dst.
func decodeJSON(r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		return errBadRequest
	}
	return nil
}

// bearerToken extracts the session token from the Authorization header.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if len(header) <= len(prefix) || header[:len(prefix)] != prefix {
		return ""
	}
	return header[len(prefix):]
}

// resolveScope rebuilds the tenant boundary for a single request entirely from
// server-side session state. Client-supplied tenant parameters are never
// trusted: a tenant admin is always pinned to the session's home tenant and a
// super admin is scoped to the tenant they selected via the validated switch
// endpoint (or to all tenants when none is selected).
func (s *Server) resolveScope(r *http.Request) (Scope, *Session, error) {
	token := bearerToken(r)
	if token == "" {
		return Scope{}, nil, errUnauthorized
	}
	session := s.store.Session(token)
	if session == nil {
		return Scope{}, nil, errUnauthorized
	}
	// Re-read the admin on every request so disabled/changed accounts take
	// effect immediately instead of trusting data baked into the session.
	admin := s.store.AdminByID(session.AdminID)
	if admin == nil {
		return Scope{}, nil, errUnauthorized
	}
	switch admin.Role {
	case RoleTenantAdmin:
		// Tenant admins can never escape their home tenant, regardless of any
		// stale ActiveTenant value left in an old session.
		return Scope{Role: RoleTenantAdmin, TenantID: admin.TenantID}, session, nil
	case RoleSuperAdmin:
		if session.ActiveTenant != "" && !s.store.TenantExists(session.ActiveTenant) {
			// The selected tenant was removed: drop the stale context rather
			// than serving data under an invalid boundary.
			return Scope{}, nil, errBadRequest
		}
		return Scope{Role: RoleSuperAdmin, TenantID: session.ActiveTenant}, session, nil
	default:
		return Scope{}, nil, errForbidden
	}
}

// scopedHandler is an HTTP handler that additionally receives the resolved scope.
type scopedHandler func(http.ResponseWriter, *http.Request, Scope)

// withScope enforces authentication and attaches the freshly resolved scope.
func (s *Server) withScope(next scopedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, _, err := s.resolveScope(r)
		if err != nil {
			writeError(w, err)
			return
		}
		next(w, r, scope)
	}
}
