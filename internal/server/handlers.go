package server

import (
	"errors"
	"net/http"

	"pkgregistry/internal/audit"
	"pkgregistry/internal/store"
	"pkgregistry/internal/token"
)

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request, ref pkgRef) {
	rec, ok := s.authenticate(w, r, token.ActionPublish, ref.namespace, ref.name, ref.version)
	if !ok {
		return
	}
	defer r.Body.Close()
	m, err := s.pkgs.Publish(ref.namespace, ref.name, ref.version, rec.ID, http.MaxBytesReader(w, r.Body, 512<<20))
	switch {
	case errors.Is(err, store.ErrExists):
		s.audit.Log(rec.ID, string(token.ActionPublish), ref.namespace, ref.name, ref.version, audit.Deny, "version already exists")
		writeJSON(w, http.StatusConflict, map[string]string{"error": "version already exists"})
	case err != nil:
		s.audit.Log(rec.ID, string(token.ActionPublish), ref.namespace, ref.name, ref.version, audit.Deny, "invalid archive: "+err.Error())
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid archive"})
	default:
		s.audit.Log(rec.ID, string(token.ActionPublish), ref.namespace, ref.name, ref.version, audit.Allow, "published sha256="+m.SHA256)
		writeJSON(w, http.StatusCreated, m)
	}
}

func (s *Server) handleFetch(w http.ResponseWriter, r *http.Request, ref pkgRef) {
	rec, ok := s.authenticate(w, r, token.ActionRead, ref.namespace, ref.name, ref.version)
	if !ok {
		return
	}
	m, f, err := s.pkgs.Fetch(ref.namespace, ref.name, ref.version)
	if err != nil {
		s.audit.Log(rec.ID, string(token.ActionRead), ref.namespace, ref.name, ref.version, audit.Deny, "package not found")
		notFound(w)
		return
	}
	defer f.Close()
	s.audit.Log(rec.ID, string(token.ActionRead), ref.namespace, ref.name, ref.version, audit.Allow, "served sha256="+m.SHA256)
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Content-SHA256", m.SHA256)
	http.ServeContent(w, r, "", m.CreatedAt, f)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, ref pkgRef) {
	rec, ok := s.authenticate(w, r, token.ActionRevoke, ref.namespace, ref.name, ref.version)
	if !ok {
		return
	}
	reason := r.URL.Query().Get("reason")
	m, err := s.pkgs.Revoke(ref.namespace, ref.name, ref.version, rec.ID, reason)
	if err != nil {
		s.audit.Log(rec.ID, string(token.ActionRevoke), ref.namespace, ref.name, ref.version, audit.Deny, "package not found")
		notFound(w)
		return
	}
	s.audit.Log(rec.ID, string(token.ActionRevoke), ref.namespace, ref.name, ref.version, audit.Allow, "revoked")
	writeJSON(w, http.StatusOK, m)
}
