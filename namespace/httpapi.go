package namespace

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const maxRequestBody = 1 << 20

type Handler struct {
	service *Service
	mux     *http.ServeMux
}

func NewHandler(service *Service) http.Handler {
	h := &Handler{service: service, mux: http.NewServeMux()}
	h.routes()
	return h.withSecurityHeaders(h.withRequestID(h.mux))
}

func (h *Handler) routes() {
	h.mux.HandleFunc("GET /{$}", h.discovery)
	h.mux.HandleFunc("GET /api/v1", h.discovery)
	h.mux.HandleFunc("GET /healthz", h.health)
	h.mux.HandleFunc("GET /api/v1/me", h.authenticated(h.me))

	h.mux.HandleFunc("GET /api/v1/policy", h.authenticated(h.policy))
	h.mux.HandleFunc("GET /api/v1/namespaces", h.authenticated(h.listNamespaces))
	h.mux.HandleFunc("GET /api/v1/namespaces/{name}", h.authenticated(h.getNamespace))
	h.mux.HandleFunc("POST /api/v1/namespaces", h.authenticated(h.legacyCreateNamespace))
	h.mux.HandleFunc("POST /api/v1/namespaces/claims", h.authenticated(h.legacyCreateNamespace))
	h.mux.HandleFunc("GET /api/v1/namespaces/claims", h.authenticated(h.listClaims))
	h.mux.HandleFunc("POST /api/v1/claims", h.authenticated(h.createClaim))
	h.mux.HandleFunc("GET /api/v1/claims", h.authenticated(h.listClaims))
	h.mux.HandleFunc("GET /api/v1/claims/{id}", h.authenticated(h.getClaim))
	h.mux.HandleFunc("POST /api/v1/claims/{id}/cancel", h.authenticated(h.cancelClaim))

	h.mux.HandleFunc("GET /api/v1/admin/claims", h.authenticated(h.adminListClaims))
	h.mux.HandleFunc("POST /api/v1/admin/claims/{id}/approve", h.authenticated(h.approveClaim))
	h.mux.HandleFunc("POST /api/v1/admin/claims/{id}/reject", h.authenticated(h.rejectClaim))

	h.mux.HandleFunc("POST /api/v1/namespaces/{name}/renew", h.authenticated(h.renew))
	h.mux.HandleFunc("POST /api/v1/namespaces/{name}/transfer", h.authenticated(h.transfer))
	h.mux.HandleFunc("GET /api/v1/namespaces/{name}/history", h.authenticated(h.namespaceHistory))
	h.mux.HandleFunc("GET /api/v1/namespaces/{name}/packages", h.authenticated(h.namespacePackages))
	h.mux.HandleFunc("POST /api/v1/packages", h.authenticated(h.publish))

	h.mux.HandleFunc("GET /api/v1/admin/audit", h.authenticated(h.listAudit))
	h.mux.HandleFunc("GET /api/v1/admin/audit/verify", h.authenticated(h.verifyAudit))
	h.mux.HandleFunc("GET /api/v1/admin/audit/export", h.authenticated(h.exportAudit))
	h.mux.HandleFunc("POST /api/v1/admin/maintenance/expire", h.authenticated(h.expireNow))
}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "namespace-ownership",
		"version": SchemaVersion,
		"docs":    "README.md",
		"endpoints": map[string]string{
			"health":       "/healthz",
			"namespaces":   "/api/v1/namespaces",
			"claims":       "/api/v1/claims",
			"audit":        "/api/v1/admin/audit",
			"audit_export": "/api/v1/admin/audit/export",
		},
	})
}

func (h *Handler) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if requestID == "" || len(requestID) > 128 {
			requestID = newID("req")
		}
		for _, char := range requestID {
			if char < 0x20 || char > 0x7e {
				requestID = newID("req")
				break
			}
		}
		w.Header().Set("X-Request-ID", requestID)
		r.Header.Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) authenticated(next func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		user, err := h.service.Authenticate(token)
		if err != nil {
			writeError(w, err)
			return
		}
		next(w, r, user)
	}
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if value != "" {
		parts := strings.Fields(value)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
	}
	return strings.TrimSpace(r.Header.Get("X-API-Token"))
}

func requestMeta(r *http.Request) RequestMeta {
	return RequestMeta{
		RequestID:  r.Header.Get("X-Request-ID"),
		RemoteAddr: r.RemoteAddr,
	}
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "namespace-ownership",
		"time":    h.service.now(),
	})
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request, user User) {
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) policy(w http.ResponseWriter, r *http.Request, user User) {
	state := h.service.store.Snapshot()
	writeJSON(w, http.StatusOK, state.Policy.normalized())
}

func (h *Handler) listNamespaces(w http.ResponseWriter, r *http.Request, user User) {
	namespaces, err := h.service.ListNamespaces()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": namespaces, "count": len(namespaces)})
}

func (h *Handler) getNamespace(w http.ResponseWriter, r *http.Request, user User) {
	view, err := h.service.GetNamespace(r.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *Handler) namespacePackages(w http.ResponseWriter, r *http.Request, user User) {
	view, err := h.service.GetNamespace(r.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": view.Packages, "count": len(view.Packages)})
}

func (h *Handler) namespaceHistory(w http.ResponseWriter, r *http.Request, user User) {
	events, err := h.service.NamespaceAudit(user, r.PathValue("name"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":        events,
		"count":        len(events),
		"verification": VerifyAudit(h.service.store.Snapshot().Audit, h.service.now()),
	})
}

func (h *Handler) legacyCreateNamespace(w http.ResponseWriter, r *http.Request, user User) {
	var body createClaimBody
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	request := body.toRequest()
	claim, err := h.service.CreateClaim(user, request, requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("X-Namespace-Creation-Mode", "approval-required")
	writeJSON(w, http.StatusAccepted, map[string]any{
		"claim":  claim,
		"status": "pending_admin_approval",
		"note":   "ordinary namespace creation only creates a claim; ownership is granted by an administrator",
	})
}

type createClaimBody struct {
	Namespace                string `json:"namespace"`
	Name                     string `json:"name"`
	Org                      string `json:"org"`
	Organization             string `json:"organization"`
	Reason                   string `json:"reason"`
	RequestedReservationDays int    `json:"requested_reservation_days"`
}

func (b createClaimBody) toRequest() CreateClaimRequest {
	namespace := b.Namespace
	if namespace == "" {
		namespace = b.Name
	}
	if namespace == "" {
		namespace = b.Org
	}
	if namespace == "" {
		namespace = b.Organization
	}
	return CreateClaimRequest{
		Namespace:                namespace,
		Reason:                   b.Reason,
		RequestedReservationDays: b.RequestedReservationDays,
	}
}

func (h *Handler) createClaim(w http.ResponseWriter, r *http.Request, user User) {
	h.createClaimWithStatus(w, r, user, http.StatusCreated)
}

func (h *Handler) createClaimWithStatus(w http.ResponseWriter, r *http.Request, user User, status int) {
	var body createClaimBody
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	claim, err := h.service.CreateClaim(user, body.toRequest(), requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, status, claim)
}

func (h *Handler) listClaims(w http.ResponseWriter, r *http.Request, user User) {
	all := r.URL.Query().Get("all") == "1" || r.URL.Query().Get("all") == "true"
	claims, err := h.service.ListClaims(user, all, r.URL.Query().Get("status"), r.URL.Query().Get("namespace"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": claims, "count": len(claims)})
}

func (h *Handler) adminListClaims(w http.ResponseWriter, r *http.Request, user User) {
	claims, err := h.service.ListClaims(user, true, r.URL.Query().Get("status"), r.URL.Query().Get("namespace"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": claims, "count": len(claims)})
}

func (h *Handler) getClaim(w http.ResponseWriter, r *http.Request, user User) {
	claim, err := h.service.GetClaim(user, r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (h *Handler) cancelClaim(w http.ResponseWriter, r *http.Request, user User) {
	claim, err := h.service.CancelClaim(user, r.PathValue("id"), requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

type approveClaimBody struct {
	ReservationDays int    `json:"reservation_days"`
	Days            int    `json:"days"`
	Note            string `json:"note"`
}

func (h *Handler) approveClaim(w http.ResponseWriter, r *http.Request, user User) {
	var body approveClaimBody
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	days := body.ReservationDays
	if days == 0 {
		days = body.Days
	}
	claim, err := h.service.ApproveClaim(user, r.PathValue("id"), ApproveClaimRequest{
		ReservationDays: days,
		Note:            body.Note,
	}, requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

type rejectClaimBody struct {
	Note   string `json:"note"`
	Reason string `json:"reason"`
}

func (h *Handler) rejectClaim(w http.ResponseWriter, r *http.Request, user User) {
	var body rejectClaimBody
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	note := body.Note
	if note == "" {
		note = body.Reason
	}
	claim, err := h.service.RejectClaim(user, r.PathValue("id"), RejectClaimRequest{Note: note}, requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

type renewBody struct {
	ReservationDays int    `json:"reservation_days"`
	Days            int    `json:"days"`
	Reason          string `json:"reason"`
}

func (h *Handler) renew(w http.ResponseWriter, r *http.Request, user User) {
	var body renewBody
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	days := body.ReservationDays
	if days == 0 {
		days = body.Days
	}
	view, err := h.service.Renew(user, r.PathValue("name"), RenewRequest{
		ReservationDays: days,
		Reason:          body.Reason,
	}, requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type transferBody struct {
	ToUserID        string `json:"to_user_id"`
	ToUser          string `json:"to_user"`
	TargetUserID    string `json:"target_user_id"`
	ReservationDays int    `json:"reservation_days"`
	Days            int    `json:"days"`
	Reason          string `json:"reason"`
}

func (h *Handler) transfer(w http.ResponseWriter, r *http.Request, user User) {
	var body transferBody
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	target := body.ToUserID
	if target == "" {
		target = body.ToUser
	}
	if target == "" {
		target = body.TargetUserID
	}
	days := body.ReservationDays
	if days == 0 {
		days = body.Days
	}
	view, err := h.service.Transfer(user, r.PathValue("name"), TransferRequest{
		ToUserID:        target,
		ReservationDays: days,
		Reason:          body.Reason,
	}, requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (h *Handler) publish(w http.ResponseWriter, r *http.Request, user User) {
	var body PublishRequest
	if err := decodeOptionalJSON(w, r, &body); err != nil {
		writeError(w, err)
		return
	}
	pkg, err := h.service.Publish(user, body, requestMeta(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, pkg)
}

func (h *Handler) listAudit(w http.ResponseWriter, r *http.Request, user User) {
	limit, err := queryInt(r, "limit", 200, 0, 10000)
	if err != nil {
		writeError(w, err)
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1<<30)
	if err != nil {
		writeError(w, err)
		return
	}
	events, err := h.service.ListAudit(user, AuditFilter{
		Namespace: r.URL.Query().Get("namespace"),
		Type:      r.URL.Query().Get("type"),
		ActorID:   r.URL.Query().Get("actor_id"),
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	state := h.service.store.Snapshot()
	verification := VerifyAudit(state.Audit, h.service.now())
	writeJSON(w, http.StatusOK, map[string]any{
		"items":        events,
		"count":        len(events),
		"verification": verification,
	})
}

func (h *Handler) verifyAudit(w http.ResponseWriter, r *http.Request, user User) {
	verification, err := h.service.VerifyAudit(user)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verification)
}

func (h *Handler) exportAudit(w http.ResponseWriter, r *http.Request, user User) {
	events, generatedAt, err := h.service.AuditSnapshot(user)
	if err != nil {
		writeError(w, err)
		return
	}
	filename := "namespace-audit-" + generatedAt.Format("20060102T150405Z") + ".tar"
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("X-Audit-Event-Count", strconv.Itoa(len(events)))
	w.Header().Set("X-Audit-Chain-Head", VerifyAudit(events, generatedAt).ChainHead)
	if err := WriteAuditTar(w, events, generatedAt); err != nil {
		return
	}
}

func (h *Handler) expireNow(w http.ResponseWriter, r *http.Request, user User) {
	if err := h.service.ExpireNow(user); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"maintained_at": h.service.now(),
	})
}

func queryInt(r *http.Request, name string, fallback, min, max int) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < min || number > max {
		return 0, validationError("%s must be an integer between %d and %d", name, min, max)
	}
	return number, nil
}

func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &Error{Code: "request_too_large", Status: 413, Message: "request body is too large"}
		}
		return validationError("invalid JSON body: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		return validationError("invalid trailing JSON: %v", err)
	} else if err == nil {
		return validationError("request body must contain exactly one JSON value")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	apiErr := asError(err)
	if apiErr.Status >= 500 {
		apiErr.Details = ""
	}
	writeJSON(w, apiErr.Status, map[string]any{"error": apiErr})
}
