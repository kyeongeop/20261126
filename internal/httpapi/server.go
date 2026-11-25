// Package httpapi exposes the file share service over net/http.
package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fileshare/internal/ratelimit"
	"fileshare/internal/shares"
	"fileshare/internal/store"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// Service wires together the share store and the throttling store.
type Service struct {
	sharesMgr *shares.Manager
	limiter   *ratelimit.Limiter
	rateStore *store.JSONFile[ratelimit.State]
	logger    *log.Logger
	// trustProxy enables reading the client IP from X-Forwarded-For. It must
	// only be enabled behind a trusted reverse proxy that overwrites the
	// header, otherwise callers could spoof their source.
	trustProxy bool
}

// NewService builds the HTTP service.
func NewService(
	sharesMgr *shares.Manager,
	rateStore *store.JSONFile[ratelimit.State],
	cfg ratelimit.Config,
	trustProxy bool,
	logger *log.Logger,
) *Service {
	return &Service{
		sharesMgr:  sharesMgr,
		limiter:    ratelimit.New(cfg, nil),
		rateStore:  rateStore,
		logger:     logger,
		trustProxy: trustProxy,
	}
}

// NewMux registers all routes.
func (s *Service) NewMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/shares", s.handleCreate)
	mux.HandleFunc("POST /api/shares/{id}/access", s.handleAccess)
	return mux
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// sourceIP extracts the request source used as the throttling identity.
func (s *Service) sourceIP(r *http.Request) string {
	if s.trustProxy {
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			// The first entry is the original client.
			first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// persistRate runs fn against the throttling document with atomic
// read-modify-write persistence.
func (s *Service) persistRate(fn func(*ratelimit.State)) error {
	return s.rateStore.Update(ratelimit.NewState(), func(state *ratelimit.State) error {
		fn(state)
		return nil
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeUnauthorized is the single error path used for both "share does not
// exist" and "wrong password", keeping responses byte-identical between the
// two cases.
func writeUnauthorized(w http.ResponseWriter) {
	writeJSON(w, http.StatusUnauthorized, map[string]any{
		"error":   "invalid_share_or_password",
		"message": "the share link or password is incorrect",
	})
}

func writeLocked(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":   "temporarily_locked",
		"message": "too many failed attempts, please try again later",
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}
