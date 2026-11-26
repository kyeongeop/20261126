package server

import (
	"net/http"
	"os"

	"fileshare/internal/freeze"
)

// denyIfFrozen enforces an active freeze for every actor, including admins
// and background jobs, and records the rejected attempt for later analysis.
// It reports true when the request has been denied.
func (s *Server) denyIfFrozen(w http.ResponseWriter, r *http.Request, sharePath, action string) bool {
	f := s.mgr.Lookup(sharePath)
	if f == nil {
		return false
	}
	a := actorFrom(r)
	s.mgr.RecordDenied(freeze.DeniedEvent{
		Path:      sharePath,
		Matched:   f.Path,
		Action:    action,
		ActorID:   a.id,
		ActorRole: a.role,
	})
	writeError(w, http.StatusForbidden, "directory_frozen",
		"directory is frozen due to an incident; access has been recorded")
	return true
}

type fileEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
}

// handleList serves directory contents at GET /api/files/{path}.
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	sharePath, abs, err := s.resolve("/" + r.PathValue("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	if s.denyIfFrozen(w, r, sharePath, "list") {
		return
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "not_found", "directory does not exist")
			return
		}
		writeError(w, http.StatusInternalServerError, "read_failed", err.Error())
		return
	}
	out := make([]fileEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "stat_failed", err.Error())
			return
		}
		out = append(out, fileEntry{Name: e.Name(), IsDir: e.IsDir(), Size: info.Size()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": sharePath, "entries": out})
}

// handleRead serves a single file's bytes at GET /api/file?path=...
func (s *Server) handleRead(w http.ResponseWriter, r *http.Request) {
	sharePath, abs, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}
	if s.denyIfFrozen(w, r, sharePath, "read") {
		return
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, "not_found", "file does not exist")
			return
		}
		writeError(w, http.StatusInternalServerError, "stat_failed", err.Error())
		return
	}
	if info.IsDir() {
		writeError(w, http.StatusBadRequest, "not_a_file", "path is a directory; use /api/files/ to list")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, abs)
}
