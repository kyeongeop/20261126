package enroll

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"certgateway/invitation"
)

// API paths exposed by NewHandler.
const (
	PathHealthz        = "/healthz"
	PathAdminInvites   = "/api/v1/invitations"
	PathEnrollBegin    = "/api/v1/enroll/begin"
	PathEnrollComplete = "/api/v1/enroll/complete"
)

// NewHandler builds the HTTP API mux. When adminToken is empty the invitation
// administration endpoint is disabled.
func NewHandler(svc *Service, adminToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathHealthz, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST "+PathAdminInvites, handleCreateInvitation(svc, adminToken))
	mux.HandleFunc("POST "+PathEnrollBegin, handleBegin(svc))
	mux.HandleFunc("POST "+PathEnrollComplete, handleComplete(svc))
	return mux
}

type createInvitationRequest struct {
	Service          string `json:"service"`
	Purpose          string `json:"purpose"`
	InviteTTLSeconds int64  `json:"invite_ttl_seconds"`
	CertTTLSeconds   int64  `json:"cert_ttl_seconds"`
}

type invitationResponse struct {
	ID             string    `json:"invitation_id"`
	Token          string    `json:"token,omitempty"`
	Service        string    `json:"service"`
	Purpose        string    `json:"purpose"`
	ExpiresAt      time.Time `json:"expires_at"`
	CertTTLSeconds int64     `json:"cert_ttl_seconds"`
}

func handleCreateInvitation(svc *Service, adminToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminToken == "" {
			writeError(w, http.StatusNotFound, "admin API disabled")
			return
		}
		if bearerToken(r) != adminToken {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		var req createInvitationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		inv, token, err := svc.Invites.Create(invitation.CreateInput{
			Service:      req.Service,
			Purpose:      req.Purpose,
			InviteTTL:    seconds(req.InviteTTLSeconds),
			CertValidity: seconds(req.CertTTLSeconds),
		})
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, invitationResponse{
			ID: inv.ID, Token: token, Service: inv.Service, Purpose: inv.Purpose,
			ExpiresAt: inv.ExpiresAt, CertTTLSeconds: int64(inv.CertValidity / time.Second),
		})
	}
}

type beginRequest struct {
	Token  string `json:"token"`
	CSRPEM string `json:"csr_pem"`
}

type beginResponse struct {
	ChallengeID string    `json:"challenge_id"`
	NonceB64    string    `json:"nonce_b64"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func handleBegin(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req beginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		res, err := svc.Begin(req.Token, []byte(req.CSRPEM))
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, beginResponse{
			ChallengeID: res.ChallengeID,
			NonceB64:    base64.StdEncoding.EncodeToString(res.Nonce),
			ExpiresAt:   res.ExpiresAt,
		})
	}
}

type completeRequest struct {
	ChallengeID  string `json:"challenge_id"`
	SignatureB64 string `json:"signature_b64"`
}

type credentialResponse struct {
	CertificatePEM string    `json:"certificate_pem"`
	ChainPEM       string    `json:"chain_pem"`
	Serial         string    `json:"serial"`
	Service        string    `json:"service"`
	Purpose        string    `json:"purpose"`
	InvitationID   string    `json:"invitation_id"`
	NotAfter       time.Time `json:"not_after"`
}

func handleComplete(svc *Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req completeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		sig, err := base64.StdEncoding.DecodeString(req.SignatureB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "signature_b64 is not valid base64")
			return
		}
		cred, err := svc.Complete(req.ChallengeID, sig)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, credentialResponse{
			CertificatePEM: string(cred.CertificatePEM),
			ChainPEM:       string(cred.ChainPEM),
			Serial:         cred.Serial,
			Service:        cred.Binding.Service,
			Purpose:        cred.Binding.Purpose,
			InvitationID:   cred.Binding.InvitationID,
			NotAfter:       cred.NotAfter,
		})
	}
}

func seconds(n int64) time.Duration {
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeServiceError maps domain errors to HTTP status codes.
func writeServiceError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, invitation.ErrInvalidService),
		errors.Is(err, invitation.ErrInvalidPurpose),
		errors.Is(err, invitation.ErrInvalidTTL),
		errors.Is(err, ErrInvalidCSR):
		status = http.StatusBadRequest
	case errors.Is(err, invitation.ErrExpired):
		status = http.StatusGone
	case errors.Is(err, invitation.ErrUsed),
		errors.Is(err, invitation.ErrRevoked),
		errors.Is(err, ErrChallengeUsed):
		status = http.StatusConflict
	case errors.Is(err, ErrSignature):
		status = http.StatusForbidden
	case errors.Is(err, invitation.ErrNotFound),
		errors.Is(err, invitation.ErrInvalidToken),
		errors.Is(err, ErrChallengeNotFound):
		status = http.StatusNotFound
	}
	writeError(w, status, err.Error())
}
