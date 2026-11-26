package server

import (
	"errors"
	"net/http"

	"fileshare/internal/freeze"
)

type freezeRequest struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type unfreezeRequestBody struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

func mapFreezeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, freeze.ErrAlreadyFrozen):
		writeError(w, http.StatusConflict, "already_frozen", err.Error())
	case errors.Is(err, freeze.ErrNotFrozen):
		writeError(w, http.StatusNotFound, "not_frozen", err.Error())
	case errors.Is(err, freeze.ErrReasonRequired):
		writeError(w, http.StatusBadRequest, "reason_required", err.Error())
	case errors.Is(err, freeze.ErrPendingExists):
		writeError(w, http.StatusConflict, "pending_exists", err.Error())
	case errors.Is(err, freeze.ErrRequestNotFound):
		writeError(w, http.StatusNotFound, "request_not_found", err.Error())
	case errors.Is(err, freeze.ErrRequestNotPending):
		writeError(w, http.StatusConflict, "request_not_pending", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

// handleFreeze is the emergency freeze entry point:
// POST /api/admin/freeze {"path":"/team-a","reason":"..."}
func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var body freezeRequest
	if !decodeBody(w, r, &body) {
		return
	}
	f, err := s.mgr.Freeze(body.Path, body.Reason, a.id)
	if err != nil {
		mapFreezeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

func (s *Server) handleListFreezes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"freezes": s.mgr.ListFreezes()})
}

// handleUnfreezeRequest starts the mandatory two-step unfreeze workflow.
// A reason is required before any administrator confirmation can happen.
func (s *Server) handleUnfreezeRequest(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var body unfreezeRequestBody
	if !decodeBody(w, r, &body) {
		return
	}
	req, err := s.mgr.RequestUnfreeze(body.Path, body.Reason, a.id)
	if err != nil {
		mapFreezeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, req)
}

// handleConfirmUnfreeze is the explicit administrator confirmation that
// finally lifts the freeze:
// POST /api/admin/unfreeze-requests/{id}/confirm
func (s *Server) handleConfirmUnfreeze(w http.ResponseWriter, r *http.Request) {
	a, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	f, err := s.mgr.ConfirmUnfreeze(r.PathValue("id"), a.id)
	if err != nil {
		mapFreezeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"unfrozen": f,
		"message":  "freeze lifted after administrator confirmation",
	})
}

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": s.mgr.ListRequests()})
}

func (s *Server) handleDenied(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	events, err := s.mgr.DeniedEvents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "log_read_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deniedAccess": events})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	entries, err := s.mgr.AuditLog()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "log_read_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": entries})
}
