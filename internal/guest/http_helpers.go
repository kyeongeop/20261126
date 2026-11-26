package guest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "guest_session"

func (h *Handler) authorizeAdmin(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return false
	}
	return constantTimeEqual(strings.TrimSpace(token), h.adminToken)
}

func (h *Handler) authenticateGuest(r *http.Request) (GuestSession, error) {
	token := ""
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		token = cookie.Value
	} else if scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok &&
		strings.EqualFold(scheme, "Bearer") {
		token = strings.TrimSpace(value)
	}
	if token == "" {
		return GuestSession{}, ErrUnauthorized
	}
	return h.service.Authenticate(token)
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		return newError("unsupported_media_type", "Content-Type must be application/json", 415)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return newError("request_too_large", "request body is too large", 413)
		}
		return newError("invalid_json", "request body must be a valid JSON object", 400)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return newError("invalid_json", "request body must contain one JSON object", 400)
	}
	return nil
}

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, err error) {
	appErr := ErrUnauthorized
	if !errors.As(err, &appErr) || appErr.HTTPStatus == 0 {
		appErr = wrapError("internal_error", "internal server error", 500, err)
	}
	body := errorBody{}
	body.Error.Code = appErr.Code
	body.Error.Message = appErr.Message
	writeJSON(w, appErr.HTTPStatus, body)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		http.Error(w, `{"error":{"code":"internal_error","message":"could not encode response"}}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buffer.Bytes())
}
