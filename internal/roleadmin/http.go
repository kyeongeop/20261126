package roleadmin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const maxJSONBody = 1 << 20

type HTTPHandler struct {
	service *Service
}

func NewHTTPHandler(service *Service) http.Handler {
	handler := &HTTPHandler{service: service}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handler.health)
	mux.HandleFunc("GET /api/roles", handler.listRoles)
	mux.HandleFunc("GET /api/roles/{roleID}", handler.getRole)
	mux.HandleFunc("POST /api/roles/{roleID}/diff", handler.previewRoleChange)
	mux.HandleFunc("POST /api/roles/{roleID}/preview", handler.previewRoleChange)
	mux.HandleFunc("POST /api/roles/{roleID}/change-requests", handler.submitRoleChange)
	mux.HandleFunc("POST /api/roles/{roleID}", handler.submitRoleChange)
	mux.HandleFunc("GET /api/change-requests", handler.listChangeRequests)
	mux.HandleFunc("GET /api/change-requests/{requestID}", handler.getChangeRequest)
	mux.HandleFunc("POST /api/change-requests/{requestID}/decision", handler.decideChangeRequest)
	mux.HandleFunc("POST /api/change-requests/{requestID}/approve", handler.approveChangeRequest)
	mux.HandleFunc("POST /api/change-requests/{requestID}/reject", handler.rejectChangeRequest)
	return recovery(mux)
}

func (h *HTTPHandler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *HTTPHandler) listRoles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"roles": h.service.ListRoles()})
}

func (h *HTTPHandler) getRole(w http.ResponseWriter, r *http.Request) {
	role, err := h.service.GetRole(r.PathValue("roleID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (h *HTTPHandler) previewRoleChange(w http.ResponseWriter, r *http.Request) {
	var update RoleUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		writeError(w, err)
		return
	}
	actorID := requestAdminID(r)
	preview, err := h.service.PreviewRoleChange(r.PathValue("roleID"), update, actorID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (h *HTTPHandler) submitRoleChange(w http.ResponseWriter, r *http.Request) {
	var update RoleUpdate
	if err := decodeJSON(w, r, &update); err != nil {
		writeError(w, err)
		return
	}
	actorID := requestAdminID(r)
	request, err := h.service.SubmitRoleChange(r.PathValue("roleID"), update, actorID)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Location", "/api/change-requests/"+request.ID)
	writeJSON(w, http.StatusCreated, request)
}

func (h *HTTPHandler) listChangeRequests(w http.ResponseWriter, r *http.Request) {
	roleID := strings.TrimSpace(r.URL.Query().Get("role_id"))
	status := ChangeStatus(strings.TrimSpace(r.URL.Query().Get("status")))
	requests := h.service.ListChangeRequests()
	filtered := make([]ChangeRequest, 0, len(requests))
	for _, request := range requests {
		if roleID != "" && request.RoleID != roleID {
			continue
		}
		if status != "" && request.Status != status {
			continue
		}
		filtered = append(filtered, request)
	}
	writeJSON(w, http.StatusOK, map[string]any{"change_requests": filtered})
}

func (h *HTTPHandler) getChangeRequest(w http.ResponseWriter, r *http.Request) {
	request, err := h.service.GetChangeRequest(r.PathValue("requestID"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func (h *HTTPHandler) decideChangeRequest(w http.ResponseWriter, r *http.Request) {
	var input DecisionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	h.applyDecision(w, r, input)
}

func (h *HTTPHandler) approveChangeRequest(w http.ResponseWriter, r *http.Request) {
	var input DecisionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	input.Decision = "approve"
	h.applyDecision(w, r, input)
}

func (h *HTTPHandler) rejectChangeRequest(w http.ResponseWriter, r *http.Request) {
	var input DecisionInput
	if err := decodeJSON(w, r, &input); err != nil {
		writeError(w, err)
		return
	}
	input.Decision = "reject"
	h.applyDecision(w, r, input)
}

func (h *HTTPHandler) applyDecision(w http.ResponseWriter, r *http.Request, input DecisionInput) {
	actorID := requestAdminID(r)
	request, err := h.service.DecideChangeRequest(r.PathValue("requestID"), actorID, input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, request)
}

func requestAdminID(r *http.Request) string {
	if adminID := strings.TrimSpace(r.Header.Get("X-Admin-ID")); adminID != "" {
		return adminID
	}
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); authorization != "" {
		if adminID, ok := strings.CutPrefix(authorization, "Bearer "); ok {
			return strings.TrimSpace(adminID)
		}
	}
	return ""
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || mediaType != "application/json" {
			return &APIError{
				Status:  http.StatusUnsupportedMediaType,
				Code:    "unsupported_media_type",
				Message: "Content-Type must be application/json",
			}
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return &APIError{
				Status:  http.StatusRequestEntityTooLarge,
				Code:    "body_too_large",
				Message: "request body exceeds 1 MiB",
			}
		}
		return badRequest("invalid_json", "invalid JSON body: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return badRequest("invalid_json", "request body must contain exactly one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	apiErr := asAPIError(err)
	writeJSON(w, apiErr.Status, map[string]any{
		"error": map[string]string{
			"code":    apiErr.Code,
			"message": apiErr.Message,
		},
	})
}

func recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				writeError(w, fmt.Errorf("panic: %v", recovered))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
