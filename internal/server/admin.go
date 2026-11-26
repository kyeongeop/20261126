package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"pkgregistry/internal/audit"
	"pkgregistry/internal/token"
)

func sha256Sum(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

// requireAdmin gates the token-admin endpoints. Failures are audited
// and answered with the same generic 404 as everything else.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request, action string) bool {
	presented := sha256Sum(bearer(r))
	if subtle.ConstantTimeCompare(presented[:], s.adminHash[:]) != 1 {
		s.audit.Log("anonymous", action, "", "", "", audit.Deny, "invalid admin credentials")
		notFound(w)
		return false
	}
	return true
}

type createTokenRequest struct {
	Label           string   `json:"label"`
	Purpose         string   `json:"purpose,omitempty"`
	Actions         []string `json:"actions,omitempty"`
	NamespacePrefix string   `json:"namespace_prefix"`
	PackagePattern  string   `json:"package_pattern,omitempty"`
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "token.create") {
		return
	}
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	var actions []token.Action
	if req.Purpose != "" {
		a, err := token.ActionsForPurpose(token.Purpose(req.Purpose))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		actions = a
	} else {
		for _, a := range req.Actions {
			actions = append(actions, token.Action(a))
		}
	}
	scope := token.Scope{
		Actions:         actions,
		NamespacePrefix: req.NamespacePrefix,
		PackagePattern:  req.PackagePattern,
	}
	secret, rec, err := s.tokens.Create(req.Label, scope)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	s.audit.Log("admin", "token.create", req.NamespacePrefix, "", "", audit.Allow,
		"created "+rec.ID+" actions="+joinActions(rec.Scope.Actions))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":  secret, // returned exactly once
		"record": rec,
	})
}

func (s *Server) handleTokenList(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "token.list") {
		return
	}
	s.audit.Log("admin", "token.list", "", "", "", audit.Allow, "listed tokens")
	writeJSON(w, http.StatusOK, s.tokens.List())
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r, "token.revoke") {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/admin/tokens/")
	if !s.tokens.Revoke(id) {
		s.audit.Log("admin", "token.revoke", "", "", "", audit.Deny, "unknown token id "+id)
		notFound(w)
		return
	}
	s.audit.Log("admin", "token.revoke", "", "", "", audit.Allow, "revoked "+id)
	writeJSON(w, http.StatusOK, map[string]string{"revoked": id})
}

func joinActions(actions []token.Action) string {
	parts := make([]string, len(actions))
	for i, a := range actions {
		parts[i] = string(a)
	}
	return strings.Join(parts, ",")
}
