package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// App 组装存储、认证与全部 HTTP 路由；实现 http.Handler。
type App struct {
	store *Store
	auth  *authConfig
	mux   *http.ServeMux
}

func NewApp(store *Store, auth *authConfig) *App {
	if auth == nil {
		auth = newAuthConfig()
	}
	a := &App{store: store, auth: auth, mux: http.NewServeMux()}
	a.routes()
	return a
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD")
	w.Header().Set("Access-Control-Allow-Headers",
		"Content-Type,Authorization,X-Actor-Id,X-Actor,X-Actor-Role,X-User-Id,X-User,X-Role,X-Authenticated-User,X-Authenticated-Role")
	w.Header().Set("Access-Control-Expose-Headers", "Location,X-Content-Sha256,Digest,X-Deletion-Pending,X-Deletion-Request")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	a.mux.ServeHTTP(w, r)
}

func (a *App) routes() {
	m := a.mux

	// 健康检查与当前身份。
	m.HandleFunc("GET /healthz", a.health)
	m.HandleFunc("GET /readyz", a.health)
	m.HandleFunc("GET /api/health", a.health)
	m.HandleFunc("GET /api/me", a.me)
	m.HandleFunc("/api/", a.apiNotFound)

	// 软件包与归档。
	m.HandleFunc("GET /api/packages", a.apiListPackages)
	m.HandleFunc("POST /api/packages", a.apiPublish)
	m.HandleFunc("GET /api/packages/{name}", a.apiGetPackage)
	m.HandleFunc("POST /api/packages/{name}/versions", a.apiPublish)
	m.HandleFunc("PUT /api/packages/{name}/versions/{version}", a.apiPublish)
	m.HandleFunc("GET /api/packages/{name}/versions/{version}", a.apiGetVersion)
	m.HandleFunc("GET /api/packages/{name}/versions/{version}/download", a.apiDownload)
	m.HandleFunc("GET /api/packages/{name}/versions/{version}/verify", a.apiVerify)
	m.HandleFunc("GET /api/packages/{name}/referenced-by", a.apiReferencedBy)

	// 兼容常见的简洁路径与 uid6-0012 风格路径。
	m.HandleFunc("POST /publish", a.publishNegotiate)
	m.HandleFunc("GET /packages/{name}/{version}/download", a.apiDownload)
	m.HandleFunc("GET /packages/{name}/{version}/manifest.json", a.apiManifest)
	m.HandleFunc("GET /packages/{name}/{version}", a.webVersionPage)
	m.HandleFunc("GET /packages/{name}", a.webPackagePage)

	// 删除冷静期 API（多种常见资源前缀，最大程度兼容调用方约定）。
	deletionPrefixes := []string{
		"/api/deletion-requests", "/deletion-requests",
		"/api/deletions", "/deletions-api",
		"/api/delete-requests", "/delete-requests",
		"/api/package-deletions", "/api/deletion_requests",
	}
	for _, prefix := range deletionPrefixes {
		m.HandleFunc("GET "+prefix, a.apiListDeletions)
		m.HandleFunc("POST "+prefix, a.apiCreateDeletion)
		m.HandleFunc("GET "+prefix+"/{id}", a.apiGetDeletion)
		m.HandleFunc("PATCH "+prefix+"/{id}", a.apiDispatchDeletion)
		m.HandleFunc("PUT "+prefix+"/{id}", a.apiDispatchDeletion)
		m.HandleFunc("POST "+prefix+"/{id}", a.apiDispatchDeletion)
		m.HandleFunc("GET "+prefix+"/{id}/impact", a.apiDeletionImpact)
		m.HandleFunc("DELETE "+prefix+"/{id}", a.apiWithdrawDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/withdraw", a.apiWithdrawDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/cancel", a.apiWithdrawDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/revoke", a.apiWithdrawDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/complete", a.apiCompleteDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/complete-cooldown", a.apiCompleteDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/expire", a.apiCompleteDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/advance", a.apiCompleteDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/mark-expired", a.apiCompleteDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/confirm", a.apiConfirmDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/approve", a.apiConfirmDeletion)
		m.HandleFunc("POST "+prefix+"/{id}/accept", a.apiConfirmDeletion)
	}

	// 以包为中心的删除别名。
	m.HandleFunc("GET /api/packages/{name}/deletion-requests", a.apiListForPackage)
	m.HandleFunc("POST /api/packages/{name}/deletion-requests", a.apiCreateDeletion)
	m.HandleFunc("GET /api/packages/{name}/deletions", a.apiListForPackage)
	m.HandleFunc("POST /api/packages/{name}/deletions", a.apiCreateDeletion)
	m.HandleFunc("GET /api/packages/{name}/deletion", a.apiActiveForPackage)
	m.HandleFunc("POST /api/packages/{name}/deletion", a.apiCreateDeletion)
	m.HandleFunc("DELETE /api/packages/{name}/deletion", a.apiWithdrawByPackage)
	m.HandleFunc("POST /api/packages/{name}/deletion/withdraw", a.apiWithdrawByPackage)
	m.HandleFunc("POST /api/packages/{name}/deletion/confirm", a.apiConfirmByPackage)
	m.HandleFunc("POST /api/packages/{name}/deletion/complete", a.apiCompleteByPackage)
	m.HandleFunc("GET /api/packages/{name}/impact", a.apiPackageImpact)

	// REST 风格 DELETE 包/版本：不立即删除，而是创建删除冷静期申请（202）。
	m.HandleFunc("DELETE /api/packages/{name}", a.apiDeletePackageResource)
	m.HandleFunc("DELETE /api/packages/{name}/versions/{version}", a.apiDeletePackageResource)
	m.HandleFunc("POST /api/packages/{name}/versions/{version}/delete", a.apiDeletePackageResource)
	m.HandleFunc("DELETE /packages/{name}", a.apiDeletePackageResource)
	m.HandleFunc("DELETE /packages/{name}/{version}", a.apiDeletePackageResource)

	// 构建、下载事件、引用关系。
	m.HandleFunc("GET /api/builds", a.apiListBuilds)
	m.HandleFunc("POST /api/builds", a.apiCreateBuild)
	m.HandleFunc("GET /api/pipelines", a.apiListBuilds)
	m.HandleFunc("POST /api/pipelines", a.apiCreateBuild)
	m.HandleFunc("GET /api/packages/{name}/builds", a.apiListBuilds)
	m.HandleFunc("POST /api/packages/{name}/builds", a.apiCreateBuild)
	m.HandleFunc("GET /api/packages/{name}/pipelines", a.apiListBuilds)
	m.HandleFunc("POST /api/packages/{name}/pipelines", a.apiCreateBuild)
	m.HandleFunc("GET /api/downloads", a.apiListDownloads)
	m.HandleFunc("POST /api/downloads", a.apiCreateDownload)
	m.HandleFunc("POST /api/download-events", a.apiCreateDownload)
	m.HandleFunc("GET /api/packages/{name}/downloads", a.apiListDownloads)
	m.HandleFunc("POST /api/packages/{name}/downloads", a.apiCreateDownload)
	m.HandleFunc("GET /api/references", a.apiListReferences)
	m.HandleFunc("POST /api/references", a.apiCreateReference)
	m.HandleFunc("POST /api/dependencies", a.apiCreateReference)
	m.HandleFunc("GET /api/packages/{name}/dependents", a.apiReferencedBy)
	m.HandleFunc("GET /api/packages/{name}/references", a.apiReferencedBy)

	// HTML 页面。
	m.HandleFunc("/", a.webDashboard)
	m.HandleFunc("GET /deletions", a.webDeletionsPage)
	m.HandleFunc("POST /deletions", a.webCreate)
	m.HandleFunc("GET /deletions/{id}", a.webDeletionDetailPage)
	m.HandleFunc("POST /deletions/{id}/withdraw", a.webWithdraw)
	m.HandleFunc("POST /deletions/{id}/complete", a.webComplete)
	m.HandleFunc("POST /deletions/{id}/confirm", a.webConfirm)
	m.HandleFunc("GET /builds", a.webBuildsPage)
	m.HandleFunc("GET /downloads", a.webDownloadsPage)
	m.HandleFunc("GET /publish", a.webPublishForm)
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"service":  "package-repository",
		"features": []string{"deletion-cooldown", "four-eyes-confirmation", "impact-analysis", "reference-protection"},
	})
}

func (a *App) apiNotFound(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error":  "api route not found",
		"code":   "not_found",
		"status": http.StatusNotFound,
		"path":   r.URL.Path,
	})
}

func (a *App) me(w http.ResponseWriter, r *http.Request) {
	p, err := a.auth.authenticate(r)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"auth_required": true,
			"trust_headers": a.auth.trustHeaders,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":        true,
		"user":                 p.User,
		"role":                 p.Role,
		"can_publish":          p.canPublish(),
		"can_request_deletion": p.canRequestDeletion(),
		"can_confirm_deletion": p.canConfirmDeletion(),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeError 把领域错误翻译为稳定的 HTTP 状态码与错误码。
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, errUnauthorized):
		status = http.StatusUnauthorized
		w.Header().Set("WWW-Authenticate", `Basic realm="pkgrepo", charset="UTF-8"`)
	case errors.Is(err, errForbidden), errors.Is(err, errSameConfirmer):
		status = http.StatusForbidden
	case errors.Is(err, errNotFound), errors.Is(err, errPackageNotFound),
		errors.Is(err, errVersionNotFound), errors.Is(err, errRequestNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errNotDue), errors.Is(err, errReferenced),
		errors.Is(err, errAlreadyPending), errors.Is(err, errInvalidTransition),
		errors.Is(err, errAlreadyPublished), errors.Is(err, errDigestMismatch):
		status = http.StatusConflict
	case errors.Is(err, errInvalidInput), errors.Is(err, errInvalidName),
		errors.Is(err, errInvalidVersion), errors.Is(err, errInvalidTar):
		status = http.StatusBadRequest
	}
	code := errorCode(err)
	writeJSON(w, status, map[string]any{
		"error":   err.Error(),
		"message": err.Error(),
		"code":    code,
		"status":  status,
		"path":    r.URL.Path,
	})
}

// fields 统一从 JSON body / 表单 / query / 路径变量读取字段。
type fields struct {
	values map[string]any
	form   map[string][]string
	query  map[string][]string
	path   map[string]string
}

func decodeFields(r *http.Request) (*fields, error) {
	f := &fields{
		values: map[string]any{},
		form:   map[string][]string{},
		query:  r.URL.Query(),
		path:   map[string]string{},
	}
	for _, name := range []string{"id", "name", "version"} {
		if v := r.PathValue(name); v != "" {
			f.path[name] = v
		}
	}
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
		if err != nil {
			return f, nil
		}
		// 恢复 body，使后续处理器可以再次解码（例如包级别路由转发到 ID 路由）。
		r.Body = io.NopCloser(bytes.NewReader(raw))
		if len(strings.TrimSpace(string(raw))) > 0 {
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, errInvalidInput
			}
			f.values = m
		}
		return f, nil
	}
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		_ = r.ParseForm()
	}
	f.form = r.Form
	return f, nil
}

func (f *fields) getString(keys ...string) string {
	for _, k := range keys {
		if v, ok := f.path[k]; ok && v != "" {
			return v
		}
	}
	for _, k := range keys {
		if v, ok := f.values[k]; ok {
			switch t := v.(type) {
			case string:
				if strings.TrimSpace(t) != "" {
					return strings.TrimSpace(t)
				}
			case float64:
				if t == float64(int64(t)) {
					return strconv.FormatInt(int64(t), 10)
				}
				return strconv.FormatFloat(t, 'f', -1, 64)
			case bool:
				if t {
					return "true"
				}
				return "false"
			}
		}
	}
	for _, k := range keys {
		if vals, ok := f.form[k]; ok && len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			return strings.TrimSpace(vals[0])
		}
		if vals, ok := f.query[k]; ok && len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			return strings.TrimSpace(vals[0])
		}
	}
	return ""
}

func (f *fields) getInt64(keys ...string) (int64, bool) {
	for _, k := range keys {
		if v, ok := f.values[k]; ok {
			switch t := v.(type) {
			case float64:
				return int64(t), true
			case string:
				if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
					return n, true
				}
			}
		}
		if vals, ok := f.form[k]; ok && len(vals) > 0 {
			if n, err := strconv.ParseInt(strings.TrimSpace(vals[0]), 10, 64); err == nil {
				return n, true
			}
		}
		if vals, ok := f.query[k]; ok && len(vals) > 0 {
			if n, err := strconv.ParseInt(strings.TrimSpace(vals[0]), 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}
