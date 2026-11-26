// Package server exposes the team file-sharing HTTP API, including the
// emergency directory freeze entry points.
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"fileshare/internal/freeze"
)

// Actor roles carried by the X-Actor-Role header. Every request must
// identify itself; there are no anonymous calls.
const (
	RoleAdmin      = "admin"
	RoleUser       = "user"
	RoleGuest      = "guest"
	RoleBackground = "background"
)

type actor struct {
	id   string
	role string
}

// Server holds the shared directory and freeze manager.
type Server struct {
	shareDir string
	mgr      *freeze.Manager
	mux      *http.ServeMux
}

// New wires routes. shareDir is the team files root; stateDir holds freeze
// state and logs outside the shared tree so freeze metadata is never served
// as file content.
func New(shareDir, stateDir string) (*Server, error) {
	if err := os.MkdirAll(shareDir, 0o750); err != nil {
		return nil, err
	}
	mgr, err := freeze.NewManager(stateDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		shareDir: filepath.Clean(shareDir),
		mgr:      mgr,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/files/{path...}", s.handleList)
	s.mux.HandleFunc("GET /api/file", s.handleRead)

	s.mux.HandleFunc("POST /api/admin/freeze", s.handleFreeze)
	s.mux.HandleFunc("GET /api/admin/freezes", s.handleListFreezes)
	s.mux.HandleFunc("POST /api/admin/unfreeze-requests", s.handleUnfreezeRequest)
	s.mux.HandleFunc("POST /api/admin/unfreeze-requests/{id}/confirm", s.handleConfirmUnfreeze)
	s.mux.HandleFunc("GET /api/admin/unfreeze-requests", s.handleListRequests)
	s.mux.HandleFunc("GET /api/admin/denied-access", s.handleDenied)
	s.mux.HandleFunc("GET /api/admin/audit", s.handleAudit)
}

// Handler exposes the router, wrapped with mandatory actor identification.
func (s *Server) Handler() http.Handler {
	return s.requireActor(s.mux)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "request body must be valid JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) requireActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Actor-Id"))
		role := strings.TrimSpace(r.Header.Get("X-Actor-Role"))
		if id == "" || role == "" {
			writeError(w, http.StatusUnauthorized, "identity_required",
				"X-Actor-Id and X-Actor-Role headers are required")
			return
		}
		switch role {
		case RoleAdmin, RoleUser, RoleGuest, RoleBackground:
		default:
			writeError(w, http.StatusUnauthorized, "unknown_role", "unknown actor role: "+role)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func actorFrom(r *http.Request) actor {
	return actor{id: r.Header.Get("X-Actor-Id"), role: r.Header.Get("X-Actor-Role")}
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (actor, bool) {
	a := actorFrom(r)
	if a.role != RoleAdmin {
		writeError(w, http.StatusForbidden, "admin_only", "administrator role required")
		return a, false
	}
	return a, true
}

// resolve maps a raw share-relative URL path to its canonical share path
// and absolute OS path, rejecting traversal attempts before any cleaning.
func (s *Server) resolve(rel string) (string, string, error) {
	for _, seg := range strings.FieldsFunc(rel, func(r rune) bool {
		return r == '/' || r == filepath.Separator
	}) {
		if seg == ".." {
			return "", "", errors.New("path traversal segments are not allowed")
		}
	}
	clean := filepath.Clean("/" + strings.TrimPrefix(rel, "/"))
	abs := filepath.Join(s.shareDir, clean)
	relToRoot, err := filepath.Rel(s.shareDir, abs)
	if err != nil || relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(os.PathSeparator)) {
		return "", "", errors.New("path outside shared directory")
	}
	sharePath := filepath.ToSlash(clean)
	return sharePath, abs, nil
}
