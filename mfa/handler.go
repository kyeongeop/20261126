package mfa

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// HTTP header names carrying the authenticated actor. A real console gateway
// sets these after session authentication; the package itself stays free of
// any external identity or database dependency.
const (
	HeaderActorID   = "X-Actor-Id"
	HeaderActorRole = "X-Actor-Role"
	// HeaderRecoveryToken carries the single-use recovery token on
	// re-registration calls made inside the recovery window.
	HeaderRecoveryToken = "X-Recovery-Token"
)

// Handler exposes the MFA reset workflow over HTTP.
type Handler struct {
	service *Service
	mux     *http.ServeMux
}

// NewHandler builds the HTTP handler with every workflow route registered.
func NewHandler(service *Service) *Handler {
	h := &Handler{service: service, mux: http.NewServeMux()}
	h.mux.HandleFunc("POST /mfa/reset-requests", h.submit)
	h.mux.HandleFunc("GET /mfa/reset-requests", h.list)
	h.mux.HandleFunc("GET /mfa/reset-requests/{id}", h.get)
	h.mux.HandleFunc("POST /mfa/reset-requests/{id}/approve", h.approve)
	h.mux.HandleFunc("POST /mfa/reset-requests/{id}/reject", h.reject)
	h.mux.HandleFunc("POST /mfa/reset-requests/{id}/revoke", h.revoke)
	h.mux.HandleFunc("POST /mfa/reset-requests/{id}/reenroll", h.reEnroll)
	h.mux.HandleFunc("POST /mfa/enroll", h.enrollAfterExpiry)
	h.mux.HandleFunc("POST /mfa/access-check", h.accessCheck)
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

type submitPayload struct {
	UserID        string `json:"user_id"`
	Reason        string `json:"reason"`
	WindowMinutes int    `json:"window_minutes"`
	NotifyMethod  string `json:"notify_method"`
	EndCondition  string `json:"end_condition"`
}

type decisionPayload struct {
	Note string `json:"note"`
}

type enrollPayload struct {
	UserID string `json:"user_id"`
	Secret string `json:"secret"`
}

type accessPayload struct {
	UserID string `json:"user_id"`
	AppID  string `json:"app_id"`
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	var in submitPayload
	if !decode(w, r, &in) {
		return
	}
	req, err := h.service.SubmitRequest(actor, SubmitInput{
		UserID:        in.UserID,
		Reason:        in.Reason,
		WindowMinutes: in.WindowMinutes,
		NotifyMethod:  NotifyMethod(in.NotifyMethod),
		EndCondition:  EndCondition(in.EndCondition),
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toRequestResponse(req))
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	reqs := h.service.ListRequests(actor)
	out := make([]requestResponse, 0, len(reqs))
	for _, req := range reqs {
		out = append(out, toRequestResponse(req))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requests": out,
	})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	req, err := h.service.GetRequest(actor, r.PathValue("id"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRequestResponse(req))
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	h.decision(w, r, h.service.Approve)
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request) {
	h.decision(w, r, h.service.Reject)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	h.decision(w, r, h.service.Revoke)
}

type serviceDecision func(Actor, string, string) (ResetRequest, error)

func (h *Handler) decision(w http.ResponseWriter, r *http.Request, fn serviceDecision) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	var in decisionPayload
	if !decode(w, r, &in) {
		return
	}
	req, err := fn(actor, r.PathValue("id"), in.Note)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRequestResponse(req))
}

func (h *Handler) reEnroll(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	token := strings.TrimSpace(r.Header.Get(HeaderRecoveryToken))
	req, err := h.service.ReEnroll(actor, r.PathValue("id"), token)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toRequestResponse(req))
}

func (h *Handler) enrollAfterExpiry(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	var in enrollPayload
	if !decode(w, r, &in) {
		return
	}
	user, err := h.service.EnrollAfterExpiry(actor, in.UserID, in.Secret)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

func (h *Handler) accessCheck(w http.ResponseWriter, r *http.Request) {
	actor, ok := actorFromRequest(w, r)
	if !ok {
		return
	}
	var in accessPayload
	if !decode(w, r, &in) {
		return
	}
	if actor.Role != RoleAdmin && actor.ID != in.UserID {
		writeError(w, http.StatusForbidden, ErrUnauthorized)
		return
	}
	decision, err := h.service.CheckAccess(in.UserID, in.AppID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAccessResponse(decision))
}

func actorFromRequest(w http.ResponseWriter, r *http.Request) (Actor, bool) {
	id := strings.TrimSpace(r.Header.Get(HeaderActorID))
	role := Role(strings.TrimSpace(r.Header.Get(HeaderActorRole)))
	if id == "" || (role != RoleUser && role != RoleAdmin) {
		writeError(w, http.StatusUnauthorized, ErrUnauthorized)
		return Actor{}, false
	}
	return Actor{ID: id, Role: role}, true
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, joinError(ErrInvalidInput, err.Error()))
		return false
	}
	return true
}

func writeServiceError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, ErrUnauthorized):
		status = http.StatusForbidden
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrContactMissing):
		status = http.StatusBadRequest
	case errors.Is(err, ErrPendingRequest), errors.Is(err, ErrInvalidTransition):
		status = http.StatusConflict
	case errors.Is(err, ErrWindowExpired), errors.Is(err, ErrInvalidRecoveryToken),
		errors.Is(err, ErrHighSensitiveBlocked), errors.Is(err, ErrMFARequired):
		status = http.StatusForbidden
	}
	writeError(w, status, err)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    errorCode(err),
			"message": err.Error(),
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
