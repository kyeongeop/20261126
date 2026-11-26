// Package server exposes the registry over net/http. All
// authentication and authorization failures return the same generic
// 404 response so clients cannot learn whether other namespace
// prefixes exist.
package server

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"

	"pkgregistry/internal/audit"
	"pkgregistry/internal/store"
	"pkgregistry/internal/token"
)

// Server is the registry HTTP handler.
type Server struct {
	tokens    *token.Store
	pkgs      *store.Store
	audit     *audit.Logger
	adminHash [32]byte
	mux       *http.ServeMux
}

// New builds a Server. adminToken gates the token-admin endpoints.
func New(tokens *token.Store, pkgs *store.Store, auditLog *audit.Logger, adminToken string) *Server {
	s := &Server{tokens: tokens, pkgs: pkgs, audit: auditLog, adminHash: sha256.Sum256([]byte(adminToken))}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/packages/", s.handlePackage)
	mux.HandleFunc("GET /v1/packages/", s.handlePackage)
	mux.HandleFunc("POST /v1/packages/", s.handlePackage)
	mux.HandleFunc("POST /v1/admin/tokens", s.handleTokenCreate)
	mux.HandleFunc("GET /v1/admin/tokens", s.handleTokenList)
	mux.HandleFunc("DELETE /v1/admin/tokens/", s.handleTokenRevoke)
	s.mux = mux
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// notFound is the single error response for missing resources and
// every authn/authz failure.
func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func bearer(r *http.Request) string {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, p) {
		return ""
	}
	return strings.TrimPrefix(h, p)
}

// authenticate resolves the request's token and checks the scope.
// Every outcome is audited; failures leave no distinguishable trace
// in the HTTP response.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, action token.Action, ns, name, version string) (token.Record, bool) {
	actor := "anonymous"
	deny := func(reason string) (token.Record, bool) {
		s.audit.Log(actor, string(action), ns, name, version, audit.Deny, reason)
		notFound(w)
		return token.Record{}, false
	}
	secret := bearer(r)
	if secret == "" {
		return deny("missing credentials")
	}
	rec, ok := s.tokens.Lookup(secret)
	if !ok {
		return deny("invalid token")
	}
	actor = rec.ID
	if !rec.Scope.Allows(action, ns, name) {
		return deny("token scope does not cover this request")
	}
	return rec, true
}

// pkgRef is the parsed target of a /v1/packages/ request.
type pkgRef struct {
	namespace string
	name      string
	version   string
	revoke    bool
	ok        bool
}

// parsePkgPath splits "<ns...>/<name>/<version>[/revoke]". Namespaces
// may be nested (e.g. "acme/billing").
func parsePkgPath(p string) pkgRef {
	rest := strings.TrimPrefix(p, "/v1/packages/")
	segs := strings.Split(rest, "/")
	ref := pkgRef{}
	if len(segs) > 0 && segs[len(segs)-1] == "revoke" {
		ref.revoke = true
		segs = segs[:len(segs)-1]
	}
	if len(segs) < 3 {
		return ref
	}
	ref.version = segs[len(segs)-1]
	ref.name = segs[len(segs)-2]
	nsSegs := segs[:len(segs)-2]
	for _, seg := range append(append([]string{}, nsSegs...), ref.name, ref.version) {
		if !store.ValidPart(seg) {
			return pkgRef{}
		}
	}
	ref.namespace = strings.Join(nsSegs, "/") + "/"
	ref.ok = true
	return ref
}

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	ref := parsePkgPath(r.URL.Path)
	if !ref.ok {
		s.audit.Log("anonymous", "parse", "", "", "", audit.Deny, "malformed package path")
		notFound(w)
		return
	}
	switch {
	case r.Method == http.MethodPut && !ref.revoke:
		s.handlePublish(w, r, ref)
	case r.Method == http.MethodGet && !ref.revoke:
		s.handleFetch(w, r, ref)
	case r.Method == http.MethodPost && ref.revoke:
		s.handleRevoke(w, r, ref)
	default:
		notFound(w)
	}
}
