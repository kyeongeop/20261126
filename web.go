package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
)

type App struct {
	store     *Store
	auth      *authConfig
	mux       *http.ServeMux
	templates map[string]*template.Template
}

func NewApp(store *Store, auth *authConfig) (*App, error) {
	app := &App{
		store:     store,
		auth:      auth,
		mux:       http.NewServeMux(),
		templates: make(map[string]*template.Template),
	}
	for name, source := range map[string]string{
		"index":   indexTemplate,
		"release": releaseTemplate,
		"publish": publishTemplate,
		"repair":  repairTemplate,
		"error":   errorTemplate,
	} {
		tmpl, err := template.New(name).Funcs(templateFuncs).Parse(source)
		if err != nil {
			return nil, fmt.Errorf("parse %s template: %w", name, err)
		}
		app.templates[name] = tmpl
	}
	app.routes()
	return app, nil
}

func (a *App) routes() {
	a.mux.HandleFunc("GET /{$}", a.index)
	a.mux.HandleFunc("GET /static/style.css", a.styles)
	a.mux.HandleFunc("GET /healthz", a.health)
	a.mux.HandleFunc("GET /publish", a.publishPage)
	a.mux.HandleFunc("POST /upload", a.uploadForm)
	a.mux.HandleFunc("GET /admin/repair", a.repairPage)
	a.mux.HandleFunc("POST /repair", a.repairForm)

	a.mux.HandleFunc("GET /packages/{name}/{version}", a.releasePage)
	a.mux.HandleFunc("GET /packages/{name}/{version}/download", a.download)
	a.mux.HandleFunc("GET /packages/{name}/{version}/manifest.json", a.manifest)
	a.mux.HandleFunc("GET /api/packages/{name}/{version}/verification", a.verification)

	a.mux.HandleFunc("POST /api/packages", a.apiPublish)
	a.mux.HandleFunc("PUT /api/packages", a.apiPublish)
	a.mux.HandleFunc("POST /api/packages/{name}/{version}", a.apiPublishVersion)
	a.mux.HandleFunc("PUT /api/packages/{name}/{version}", a.apiPublishVersion)
	a.mux.HandleFunc("POST /api/packages/{name}/{version}/repair", a.apiRepair)
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	a.mux.ServeHTTP(w, r)
}

func (a *App) index(w http.ResponseWriter, r *http.Request) {
	releases, err := a.store.List()
	if err != nil {
		a.renderError(w, http.StatusInternalServerError, "无法读取软件包", "读取发布索引失败。")
		return
	}
	views := make([]releaseView, 0, len(releases))
	for _, release := range releases {
		views = append(views, releaseView{
			Release:      release,
			Verification: a.store.Verify(release),
		})
	}
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, "index", http.StatusOK, pageData{Title: "内部软件包仓库", Releases: views})
}

func (a *App) styles(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write([]byte(styleCSS))
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *App) publishPage(w http.ResponseWriter, r *http.Request) {
	user, err := a.auth.requireRole(r, rolePublisher)
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	a.render(w, "publish", http.StatusOK, pageData{
		Title:    "发布新版本",
		Identity: &user,
	})
}

func (a *App) repairPage(w http.ResponseWriter, r *http.Request) {
	user, err := a.auth.requireRole(r, roleAdmin)
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	a.render(w, "repair", http.StatusOK, pageData{
		Title:    "创建修复版本",
		Identity: &user,
	})
}

func (a *App) releasePage(w http.ResponseWriter, r *http.Request) {
	name, version := r.PathValue("name"), r.PathValue("version")
	release, err := a.store.Release(name, version)
	if err != nil {
		if os.IsNotExist(err) {
			a.renderError(w, http.StatusNotFound, "版本不存在", "找不到该软件包版本。")
			return
		}
		a.renderError(w, http.StatusInternalServerError, "读取失败", "无法读取发布记录。")
		return
	}
	view := releaseView{Release: release, Verification: a.store.Verify(release)}
	w.Header().Set("X-Signature-Verification", verificationStatus(view.Verification))
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, "release", http.StatusOK, pageData{
		Title:   release.Name + " " + release.Version,
		Release: &view,
	})
}

func (a *App) manifest(w http.ResponseWriter, r *http.Request) {
	release, err := a.store.Release(r.PathValue("name"), r.PathValue("version"))
	if err != nil {
		httpError(w, http.StatusNotFound, "not_found", "release not found")
		return
	}
	verification := a.store.Verify(release)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Signature-Verification", verificationStatus(verification))
	w.Header().Set("X-Content-SHA256", release.ContentDigest)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(release)
}

func (a *App) download(w http.ResponseWriter, r *http.Request) {
	release, err := a.store.Release(r.PathValue("name"), r.PathValue("version"))
	if err != nil {
		httpError(w, http.StatusNotFound, "not_found", "release not found")
		return
	}
	f, verification, err := a.store.OpenVerified(release)
	if err != nil {
		a.renderError(w, http.StatusConflict, "归档验证失败", verification.Detail+" 下载已拒绝。")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.tar"`, release.Name, release.Version))
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Signature-Verification", verificationStatus(verification))
	w.Header().Set("X-Content-SHA256", release.ContentDigest)
	http.ServeContent(w, r, release.Name+"-"+release.Version+".tar", release.PublishedAt, f)
}

func (a *App) verification(w http.ResponseWriter, r *http.Request) {
	release, err := a.store.Release(r.PathValue("name"), r.PathValue("version"))
	if err != nil {
		httpError(w, http.StatusNotFound, "not_found", "release not found")
		return
	}
	verification := a.store.Verify(release)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":         release.Name,
		"version":      release.Version,
		"publisher":    release.Publisher,
		"signature":    release.Signature,
		"verification": verification,
	})
}

func (a *App) render(w http.ResponseWriter, name string, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.templates[name].Execute(w, data); err != nil {
		log.Printf("render template %s: %v", name, err)
		return
	}
}

func (a *App) renderError(w http.ResponseWriter, status int, title, message string) {
	a.render(w, "error", status, pageData{Title: title, Error: message})
}

func (a *App) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errNoCredentials) || errors.Is(err, errBadCredentials) {
		w.Header().Set("WWW-Authenticate", `Basic realm="immutable package repository", charset="UTF-8"`)
		if wantsJSON(r) {
			httpError(w, http.StatusUnauthorized, "authentication_required", "valid credentials are required")
			return
		}
		a.renderError(w, http.StatusUnauthorized, "需要登录", "该操作需要有效身份。")
		return
	}
	if errors.Is(err, errForbidden) {
		if wantsJSON(r) {
			httpError(w, http.StatusForbidden, "forbidden", "your role is not allowed to perform this action")
			return
		}
		a.renderError(w, http.StatusForbidden, "无权操作", "当前角色无权执行该操作。")
		return
	}
	a.renderError(w, http.StatusInternalServerError, "认证失败", "无法完成身份验证。")
}

func verificationStatus(v Verification) string {
	if v.Valid {
		return "valid"
	}
	return "invalid"
}

func wantsJSON(r *http.Request) bool {
	return r.URL.Path == "/api" ||
		len(r.URL.Path) > 5 && r.URL.Path[:5] == "/api/" ||
		r.Header.Get("Accept") == "application/json"
}

func httpError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
