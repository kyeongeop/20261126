package httpapi

import (
	"errors"
	"net/http"
	"time"

	"fileshare/internal/ratelimit"
	"fileshare/internal/shares"
)

type createRequest struct {
	Filename string `json:"filename"`
	Password string `json:"password"`
	Content  []byte `json:"content"`
}

type createResponse struct {
	ShareID   string `json:"share_id"`
	AccessURL string `json:"access_url"`
	CreatedAt string `json:"created_at"`
}

type accessRequest struct {
	Password string `json:"password"`
}

type accessResponse struct {
	Filename string `json:"filename"`
	Content  []byte `json:"content"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request_body",
		})
		return
	}
	if req.Filename == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "filename_and_password_required",
		})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	record, err := s.sharesMgr.Create(req.Filename, req.Password, req.Content, now)
	if err != nil {
		s.logger.Printf("create share failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "internal_error",
		})
		return
	}

	writeJSON(w, http.StatusCreated, createResponse{
		ShareID:   record.ID,
		AccessURL: "/api/shares/" + record.ID + "/access",
		CreatedAt: record.CreatedAt,
	})
}

func (s *Service) handleAccess(w http.ResponseWriter, r *http.Request) {
	shareID := r.PathValue("id")
	source := s.sourceIP(r)
	key := ratelimit.Key(shareID, source)

	var req accessRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request_body",
		})
		return
	}

	// Step 1: enforce the persisted lock / window quota. Throttling is
	// checked before any password work so locked sources cannot spend
	// server CPU on guessing attempts.
	var lockErr *ratelimit.LockError
	err := s.persistRate(func(state *ratelimit.State) {
		if err := s.limiter.BeginRequest(state, key); err != nil {
			var le *ratelimit.LockError
			if errors.As(err, &le) {
				lockErr = le
			}
		}
	})
	if err != nil {
		s.logger.Printf("rate state update failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	if lockErr != nil {
		writeLocked(w, lockErr.RetryAfter)
		return
	}

	// Step 2: verify. Unknown share IDs perform an equivalent dummy
	// derivation inside Verify, so timing matches the wrong-password case.
	_, ok, err := s.sharesMgr.Verify(shareID, req.Password)
	if err != nil {
		s.logger.Printf("verification failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	// Step 3: persist the outcome so consecutive failures and successful
	// resets survive restarts.
	if perr := s.persistRate(func(state *ratelimit.State) {
		s.limiter.RecordResult(state, key, ok)
	}); perr != nil {
		s.logger.Printf("rate state update failed: %v", perr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	if !ok {
		// Same body and status whether the share is missing or the
		// password is wrong.
		writeUnauthorized(w)
		return
	}

	if err := s.sharesMgr.View(shareID, func(record shares.Record) error {
		writeJSON(w, http.StatusOK, accessResponse{
			Filename: record.Filename,
			Content:  record.Content,
		})
		return nil
	}); err != nil {
		s.logger.Printf("load share failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
}

// SweepExpired prunes idle throttling entries. It should be called
// periodically from the main goroutine.
func (s *Service) SweepExpired() error {
	return s.persistRate(func(state *ratelimit.State) {
		s.limiter.Sweep(state)
	})
}
