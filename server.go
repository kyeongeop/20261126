package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Server is the protected internal package registry HTTP service.
type Server struct {
	Store *Store
	Guard *Guard

	// PublishToken, when set, requires "Authorization: Bearer <token>" or
	// "X-Publish-Token" on publish requests.
	PublishToken string

	// UpstreamBase optionally enables an explicit public fallback for
	// *unreserved* names only. Reserved internal names never reach it.
	UpstreamBase string
	HTTPClient   *http.Client
}

// NewServer builds a Server with the dependency-confusion guard.
func NewServer(store *Store, guard *Guard) *Server {
	if guard == nil {
		guard = &Guard{Classifier: NewClassifier(NamespacePolicy{Fallback: "deny"})}
	}
	if guard.Classifier == nil {
		guard.Classifier = NewClassifier(NamespacePolicy{Fallback: "deny"})
	}
	return &Server{Store: store, Guard: guard}
}

// Handler returns the routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/packages", s.handleList)
	mux.HandleFunc("GET /v1/release", s.handleRelease)
	mux.HandleFunc("GET /v1/tarball", s.handleTarball)
	mux.HandleFunc("/v1/publish", s.handlePublish)
	return securityHeaders(mux)
}

// ListenAndServe starts the registry.
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Dependency-Confusion-Protection", "reserved-names-internal-only")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"protection": "dependency-confusion",
		"fallback":   "denied-for-reserved-names",
	})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"packages": s.Store.Names()})
}

func (s *Server) handleRelease(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	version := r.URL.Query().Get("version")
	if name == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'name' is required")
		return
	}
	decision := s.Guard.Evaluate(name)

	if decision.Internal {
		rel, err := s.Store.ReleaseMetadata(name, version)
		if errors.Is(err, ErrReleaseNotFound) {
			s.writeProtectedNotFound(w, decision)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		q := url.Values{}
		q.Set("name", rel.Name)
		q.Set("version", rel.Version)
		rel.TarballURL = absoluteURL(r, "/v1/tarball?"+q.Encode())
		writeJSON(w, http.StatusOK, rel)
		return
	}

	if decision.Action == ActionPublicAllowed && s.UpstreamBase != "" {
		s.proxyUpstream(w, r)
		return
	}
	s.writeGuardDenied(w, decision)
}

func (s *Server) handleTarball(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	version := r.URL.Query().Get("version")
	if name == "" {
		writeError(w, http.StatusBadRequest, "query parameter 'name' is required")
		return
	}
	decision := s.Guard.Evaluate(name)

	if decision.Internal {
		rel, blob, err := s.Store.Get(name, version)
		if errors.Is(err, ErrReleaseNotFound) {
			s.writeProtectedNotFound(w, decision)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Re-verify content digest on download.
		if got := DigestBytes(blob); got != rel.SHA256 {
			writeError(w, http.StatusInternalServerError, "stored artifact sha256 verification failed")
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Digest", rel.SHA256)
		w.Header().Set("X-Checksum-SHA256", trimPrefix(rel.SHA256, SHA256Prefix))
		w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
		_, _ = w.Write(blob)
		return
	}

	if decision.Action == ActionPublicAllowed && s.UpstreamBase != "" {
		s.proxyUpstream(w, r)
		return
	}
	s.writeGuardDenied(w, decision)
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		w.Header().Set("Allow", "PUT, POST")
		writeError(w, http.StatusMethodNotAllowed, "use PUT or POST")
		return
	}
	if s.PublishToken != "" {
		token := r.Header.Get("X-Publish-Token")
		if token == "" {
			token = bearerToken(r.Header.Get("Authorization"))
		}
		if token != s.PublishToken {
			writeError(w, http.StatusUnauthorized, "invalid or missing publish token")
			return
		}
	}

	name := r.URL.Query().Get("name")
	version := r.URL.Query().Get("version")
	if name == "" || version == "" {
		writeError(w, http.StatusBadRequest, "query parameters 'name' and 'version' are required")
		return
	}

	const maxPublish = 64 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxPublish)
	blob, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read tar body: "+err.Error())
		return
	}

	rel, err := s.Store.Publish(name, version, blob)
	if errors.Is(err, ErrVersionExists) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q := url.Values{}
	q.Set("name", rel.Name)
	q.Set("version", rel.Version)
	rel.TarballURL = absoluteURL(r, "/v1/tarball?"+q.Encode())
	writeJSON(w, http.StatusCreated, rel)
}

// proxyUpstream forwards a GET to the configured public upstream. It is only
// reachable for unreserved names that the Guard marks public-allowed.
func (s *Server) proxyUpstream(w http.ResponseWriter, r *http.Request) {
	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	target := stringsTrimSlash(s.UpstreamBase) + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "public upstream unavailable: "+err.Error())
		return
	}
	defer resp.Body.Close()
	copyHeader := w.Header()
	for k, vs := range resp.Header {
		for _, v := range vs {
			copyHeader.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) writeProtectedNotFound(w http.ResponseWriter, d Decision) {
	w.Header().Set("X-Depguard-Protection", "reserved-no-public-fallback")
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error":    "package is reserved internally but has no published internal release",
		"name":     d.Name,
		"decision": d,
		"dependency_confusion_protection": map[string]any{
			"blocked":                      true,
			"public_fallback_performed":    false,
			"public_catalog_has_same_name": d.PublicHasSameName,
			"action":                       string(d.Action),
			"remediation":                  "publish the package to the internal registry; do not fetch it from a public mirror",
		},
	})
}

func (s *Server) writeGuardDenied(w http.ResponseWriter, d Decision) {
	w.Header().Set("X-Depguard-Protection", "unmanaged-no-public-proxy")
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error":    d.Reason,
		"name":     d.Name,
		"decision": d,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func bearerToken(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

func absoluteURL(r *http.Request, ref string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fp := r.Header.Get("X-Forwarded-Proto"); fp != "" {
		scheme = fp
	}
	return scheme + "://" + r.Host + ref
}

func trimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}
