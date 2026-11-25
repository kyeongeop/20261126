// Package server exposes the one-time preview token service over net/http
// using encoding/json for its API payloads.
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"previewtoken/token"
)

// Server wires the token Manager to HTTP handlers.
type Server struct {
	mgr        *token.Manager
	contentDir string
}

// Option customizes a Server.
type Option func(*Server)

// WithContentDir enables serving real preview bytes from dir.
// Layout: <dir>/<file>/versions/<version>.
func WithContentDir(dir string) Option {
	return func(s *Server) { s.contentDir = dir }
}

// New creates a Server.
func New(mgr *token.Manager, opts ...Option) *Server {
	s := &Server{mgr: mgr}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Handler returns the fully routed http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ping", s.handleHealth)

	// Token lifecycle (JSON API).
	mux.HandleFunc("POST /api/preview/tokens", s.handleIssueToken)
	mux.HandleFunc("POST /api/preview/token", s.handleIssueToken)
	mux.HandleFunc("POST /api/preview/issue", s.handleIssueToken)
	mux.HandleFunc("POST /api/preview", s.handleIssueToken)
	mux.HandleFunc("POST /api/preview/batch", s.handleIssueBatch)
	mux.HandleFunc("POST /api/preview/batch-tokens", s.handleIssueBatch)
	mux.HandleFunc("POST /api/preview/thumbnails", s.handleIssueBatch)
	mux.HandleFunc("POST /api/preview/session", s.handleSession)
	mux.HandleFunc("POST /api/preview/verify", s.handleVerify)
	mux.HandleFunc("POST /api/preview/validate", s.handleValidate)
	mux.HandleFunc("POST /api/preview/check", s.handleValidate)

	// Token consumption / preview endpoints.
	mux.HandleFunc("GET /preview", s.handlePreview)
	mux.HandleFunc("GET /preview/{token}", s.handlePreview)
	mux.HandleFunc("GET /preview/thumbnail", s.handleThumbnail)
	mux.HandleFunc("GET /files/", s.handleFilePathPreview)
	mux.HandleFunc("GET /api/preview", s.handlePreview)

	// Human-facing demo page.
	mux.HandleFunc("GET /demo", s.handleDemo)
	mux.HandleFunc("GET /{$}", s.handleDemo)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

// ---- Shared DTOs ---------------------------------------------------------

type issueTokenRequest struct {
	File       string     `json:"file"`
	Filename   string     `json:"filename"`
	FileName   string     `json:"file_name"`
	Version    string     `json:"version"`
	Ver        string     `json:"ver"`
	User       string     `json:"user"`
	UserID     string     `json:"user_id"`
	Username   string     `json:"username"`
	Purpose    string     `json:"purpose"`
	TTL        duration   `json:"ttl"`
	TTLSeconds int64      `json:"ttl_seconds"`
	ExpiresAt  *time.Time `json:"expires_at"`
	Item       string     `json:"item"`
	Items      []string   `json:"items"`
}

type tokenResponse struct {
	Token       string       `json:"token"`
	AccessToken string       `json:"access_token,omitempty"`
	TokenType   string       `json:"token_type"`
	Claims      token.Claims `json:"claims"`
	ExpiresAt   time.Time    `json:"expires_at"`
	PreviewURL  string       `json:"preview_url,omitempty"`
	URL         string       `json:"url,omitempty"`
}

type errorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// duration accepts both Go duration strings ("90s", "10m") and JSON numbers
// interpreted as seconds.
type duration time.Duration

func (d *duration) UnmarshalJSON(raw []byte) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	switch v := value.(type) {
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return err
		}
		*d = duration(parsed)
	case float64:
		*d = duration(time.Duration(v * float64(time.Second)))
	}
	return nil
}

func (r issueTokenRequest) file() string {
	return firstNonEmpty(r.File, r.Filename, r.FileName)
}

func (r issueTokenRequest) version() string {
	return firstNonEmpty(r.Version, r.Ver)
}

func (r issueTokenRequest) user() string {
	return firstNonEmpty(r.User, r.UserID, r.Username)
}

func (r issueTokenRequest) ttl() time.Duration {
	if r.TTLSeconds > 0 {
		return time.Duration(r.TTLSeconds) * time.Second
	}
	if r.TTL > 0 {
		return time.Duration(r.TTL)
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func classifyError(err error) (int, string) {
	switch {
	case errors.Is(err, token.ErrExpired):
		return http.StatusUnauthorized, "expired"
	case errors.Is(err, token.ErrReplay):
		// A consumed one-time credential is no longer valid.
		return http.StatusUnauthorized, "replayed"
	case errors.Is(err, token.ErrBinding):
		return http.StatusForbidden, "binding_mismatch"
	case errors.Is(err, token.ErrItemNotAllowed):
		return http.StatusForbidden, "item_not_allowed"
	case errors.Is(err, token.ErrUnknownToken):
		return http.StatusUnauthorized, "unknown_token"
	case errors.Is(err, token.ErrInvalidToken):
		return http.StatusUnauthorized, "invalid_token"
	case errors.Is(err, token.ErrItemRequired):
		return http.StatusBadRequest, "item_required"
	case errors.Is(err, token.ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request"
	default:
		return http.StatusInternalServerError, "internal"
	}
}

func (s *Server) writeTokenError(w http.ResponseWriter, err error) {
	status, reason := classifyError(err)
	writeJSON(w, status, errorResponse{Error: err.Error(), Reason: reason})
}

// tokenFromRequest extracts a token from ?token=, ?batch_token=, the
// X-Preview-Token header or an Authorization: Bearer header.
func tokenFromRequest(r *http.Request) string {
	if v := r.PathValue("token"); v != "" {
		return v
	}
	if v := r.URL.Query().Get("token"); v != "" {
		return v
	}
	if v := r.URL.Query().Get("batch_token"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Preview-Token"); v != "" {
		return v
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func bindingFromRequest(r *http.Request) token.Binding {
	q := r.URL.Query()
	return token.Binding{
		File: firstNonEmpty(
			r.PathValue("file"),
			q.Get("file"), q.Get("filename"), q.Get("file_name"),
		),
		Version: firstNonEmpty(
			r.PathValue("version"),
			q.Get("version"), q.Get("ver"),
		),
		User: firstNonEmpty(
			r.Header.Get("X-User-ID"),
			q.Get("user"), q.Get("user_id"),
		),
		Item: firstNonEmpty(q.Get("item"), q.Get("thumbnail")),
	}
}
