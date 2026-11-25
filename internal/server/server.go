package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"teamsync/internal/model"
	"teamsync/internal/perm"
	"teamsync/internal/store"
)

// Server wires the store, the permission engine and the editor UI together.
type Server struct {
	store *store.Store
	mux   *http.ServeMux
}

// New builds the single-process HTTP handler.
func New(st *store.Store) http.Handler {
	s := &Server{store: st, mux: http.NewServeMux()}
	s.routes()
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/users", s.handleListUsers)
	s.mux.HandleFunc("POST /api/users", s.handleCreateUser)
	s.mux.HandleFunc("GET /api/nodes", s.handleListNodes)
	s.mux.HandleFunc("POST /api/nodes", s.handleCreateNode)
	s.mux.HandleFunc("GET /api/nodes/{id}", s.handleGetNode)
	s.mux.HandleFunc("POST /api/nodes/{id}/move", s.handleMoveNode)
	s.mux.HandleFunc("GET /api/nodes/{id}/permissions", s.handlePermissions)
	s.mux.HandleFunc("PUT /api/nodes/{id}/permissions/{userId}", s.handleSetACE)
	s.mux.HandleFunc("DELETE /api/nodes/{id}/permissions/{userId}", s.handleDeleteACE)
	s.mux.HandleFunc("GET /", s.handleEditor)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

// actorID extracts the acting user. Requests without an actor are treated as
// bootstrap/admin requests so the API stays usable before any user exists;
// requests that name an actor are fully permission-checked.
func actorID(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Actor-Id"))
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, perm.ErrNodeNotFound):
		return http.StatusNotFound
	case errors.Is(err, store.ErrUserNotFound):
		return http.StatusNotFound
	case errors.Is(err, store.ErrNameConflict),
		errors.Is(err, store.ErrInvalidName),
		errors.Is(err, store.ErrInvalidKind),
		errors.Is(err, store.ErrParentFolder),
		errors.Is(err, perm.ErrInvalidLevel):
		return http.StatusBadRequest
	case errors.Is(err, store.ErrMoveRoot), errors.Is(err, store.ErrMoveIntoSelf):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) require(w http.ResponseWriter, r *http.Request, nodeID, level string) bool {
	actor := actorID(r)
	if actor == "" {
		return true
	}
	ok, err := perm.Can(s.store, nodeID, actor, level)
	if err != nil {
		writeError(w, statusFor(err), err)
		return false
	}
	if !ok {
		writeError(w, http.StatusForbidden, errors.New("permission denied: "+level+" access required"))
		return false
	}
	return true
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type createUserReq struct {
	Name string `json:"name"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"users": s.store.Users()})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if !decode(w, r, &req) {
		return
	}
	user, err := s.store.CreateUser(req.Name)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

type createNodeReq struct {
	Name     string      `json:"name"`
	Kind     string      `json:"kind"`
	ParentID string      `json:"parentId"`
	Direct   []model.ACE `json:"direct"`
}

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"nodes": s.store.Nodes(), "rootId": s.store.RootID()})
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req createNodeReq
	if !decode(w, r, &req) {
		return
	}
	parentID := req.ParentID
	if parentID == "" {
		parentID = s.store.RootID()
	}
	if !s.require(w, r, parentID, model.LevelWrite) {
		return
	}
	node, err := s.store.CreateNode(req.Name, req.Kind, parentID, req.Direct)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, node)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, ok := s.store.Node(id)
	if !ok {
		writeError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	if !s.require(w, r, id, model.LevelRead) {
		return
	}
	writeJSON(w, http.StatusOK, node)
}

type moveReq struct {
	NewParentID string `json:"newParentId"`
}

func (s *Server) handleMoveNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req moveReq
	if !decode(w, r, &req) {
		return
	}
	// Admin on the node and write access on the destination are both required.
	if !s.require(w, r, id, model.LevelAdmin) {
		return
	}
	if !s.require(w, r, req.NewParentID, model.LevelWrite) {
		return
	}
	node, err := s.store.Move(id, req.NewParentID)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": node, "message": "effective permissions recomputed from the new location"})
}

func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.require(w, r, id, model.LevelRead) {
		return
	}
	view, err := s.store.Effective(id)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type aceReq struct {
	Level string `json:"level"`
}

func (s *Server) handleSetACE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.PathValue("userId")
	var req aceReq
	if !decode(w, r, &req) {
		return
	}
	if !s.require(w, r, id, model.LevelAdmin) {
		return
	}
	ace, err := s.store.SetACE(id, userID, req.Level)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, ace)
}

func (s *Server) handleDeleteACE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	userID := r.PathValue("userId")
	if !s.require(w, r, id, model.LevelAdmin) {
		return
	}
	if err := s.store.DeleteACE(id, userID); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
