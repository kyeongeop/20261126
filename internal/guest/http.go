package guest

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HTTPConfig struct {
	AdminToken    string
	InviterName   string
	SecureCookies bool
}

type Handler struct {
	service       *Service
	adminToken    string
	inviterName   string
	secureCookies bool
	mux           *http.ServeMux
}

func NewHandler(service *Service, config HTTPConfig) (*Handler, error) {
	if service == nil {
		return nil, fmt.Errorf("service is required")
	}
	if config.AdminToken == "" {
		return nil, fmt.Errorf("admin token is required")
	}
	inviterName := strings.TrimSpace(config.InviterName)
	if inviterName == "" {
		inviterName = "team"
	}
	handler := &Handler{
		service:       service,
		adminToken:    config.AdminToken,
		inviterName:   inviterName,
		secureCookies: config.SecureCookies,
		mux:           http.NewServeMux(),
	}
	handler.routes()
	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	defer func() {
		if recovered := recover(); recovered != nil {
			writeError(w, wrapError("internal_error", "internal server error", 500, fmt.Errorf("panic: %v", recovered)))
		}
	}()
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /{$}", h.handleIndex)
	h.mux.HandleFunc("GET /healthz", h.handleHealth)

	h.mux.HandleFunc("POST /api/invitations", h.handleCreateInvitation)
	h.mux.HandleFunc("GET /api/invitations", h.handleListInvitations)
	h.mux.HandleFunc("DELETE /api/invitations/{id}", h.handleRevokeInvitation)
	h.mux.HandleFunc("POST /api/invitations/{id}/revoke", h.handleRevokeInvitation)

	h.mux.HandleFunc("POST /api/guest/join", h.handleJoin)
	h.mux.HandleFunc("GET /api/guest/session", h.handleGuestSession)
	h.mux.HandleFunc("POST /api/guest/logout", h.handleGuestLogout)
	h.mux.HandleFunc("GET /api/guest/files", h.handleListDirectory)
	h.mux.HandleFunc("GET /api/guest/files/{path...}", h.handleDownload)
}

type createInvitationRequest struct {
	DisplayName string `json:"display_name"`
	Passcode    string `json:"passcode"`
	Directory   string `json:"directory"`
	ExpiresAt   string `json:"expires_at"`
}

type createInvitationResponse struct {
	Invitation      InvitationView `json:"invitation"`
	InvitationToken string         `json:"invitation_token"`
}

type joinRequest struct {
	Token    string `json:"token"`
	Passcode string `json:"passcode"`
}

type joinResponse struct {
	Guest        GuestView `json:"guest"`
	SessionToken string    `json:"session_token"`
}

func (h *Handler) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeAdmin(r) {
		writeError(w, ErrUnauthorized)
		return
	}
	var request createInvitationRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(request.ExpiresAt))
	if err != nil {
		writeError(w, newError("invalid_request", "expires_at must be an RFC3339 timestamp", 400))
		return
	}
	result, err := h.service.CreateInvitation(CreateInvitationParams{
		Inviter:     h.inviterName,
		DisplayName: request.DisplayName,
		Passcode:    request.Passcode,
		Directory:   request.Directory,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createInvitationResponse{
		Invitation:      result.Invitation,
		InvitationToken: result.InvitationToken,
	})
}

func (h *Handler) handleListInvitations(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeAdmin(r) {
		writeError(w, ErrUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"invitations": h.service.ListInvitations(h.inviterName),
	})
}

func (h *Handler) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.authorizeAdmin(r) {
		writeError(w, ErrUnauthorized)
		return
	}
	invitation, err := h.service.RevokeInvitation(h.inviterName, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invitation": invitation})
}

func (h *Handler) handleJoin(w http.ResponseWriter, r *http.Request) {
	var request joinRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, err)
		return
	}
	result, err := h.service.Join(request.Token, request.Passcode)
	if err != nil {
		writeError(w, err)
		return
	}
	h.setSessionCookie(w, result.SessionToken, result.Guest.ExpiresAt)
	writeJSON(w, http.StatusOK, joinResponse{
		Guest:        result.Guest,
		SessionToken: result.SessionToken,
	})
}

func (h *Handler) handleGuestSession(w http.ResponseWriter, r *http.Request) {
	session, err := h.authenticateGuest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"guest": GuestView{
			DisplayName: session.Invitation.DisplayName,
			Directory:   session.Invitation.Directory,
			ExpiresAt:   session.Invitation.ExpiresAt,
		},
	})
}

func (h *Handler) handleGuestLogout(w http.ResponseWriter, r *http.Request) {
	h.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (h *Handler) handleListDirectory(w http.ResponseWriter, r *http.Request) {
	session, err := h.authenticateGuest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	requestedPath := r.URL.Query().Get("path")
	entries, err := h.service.ListDirectory(session, requestedPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authorized_directory": session.Invitation.Directory,
		"path":                 requestedPath,
		"entries":              entries,
	})
}

func (h *Handler) handleDownload(w http.ResponseWriter, r *http.Request) {
	session, err := h.authenticateGuest(r)
	if err != nil {
		writeError(w, err)
		return
	}
	file, info, err := h.service.OpenGuestFile(session, r.PathValue("path"))
	if err != nil {
		writeError(w, err)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name": "guestshare",
		"endpoints": []string{
			"POST /api/invitations",
			"GET /api/invitations",
			"DELETE /api/invitations/{id}",
			"POST /api/guest/join",
			"GET /api/guest/session",
			"GET /api/guest/files?path=...",
			"GET /api/guest/files/{path}",
		},
	})
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
