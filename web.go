package main

import (
	"errors"
	"html/template"
	"net/http"
)

func wantsHTML(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return false
	}
	_ = r.ParseForm()
	if r.Form.Get("format") == "json" {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	return stringContains(accept, "text/html")
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

var layoutTemplate = template.Must(template.New("layout").Funcs(template.FuncMap(funcMap)).Parse(layoutHTML))

func renderPage(w http.ResponseWriter, status int, page string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if _, ok := data["Title"]; !ok {
		data["Title"] = "内部软件包仓库"
	}
	tmpl, err := template.Must(layoutTemplate.Clone()).Parse(page)
	if err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		// 响应可能已部分写出，只能中断。
		_ = err
	}
}

func (a *App) webDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	pkgs := a.store.ListPackages(false)
	deletions := a.store.ListDeletions()
	builds := a.store.ListBuilds("")
	downloads := a.store.ListDownloads("")
	activeDeletions := 0
	runningBuilds := 0
	for _, d := range deletions {
		if d.Status == StatusPending || d.Status == StatusCooldownCompleted {
			activeDeletions++
		}
	}
	for _, b := range builds {
		if isActiveBuild(b.Status) {
			runningBuilds++
		}
	}
	renderPage(w, http.StatusOK, dashboardPage, map[string]any{
		"Title":         "总览",
		"Active":        "home",
		"Packages":      pkgs,
		"Deletions":     deletions,
		"RecentBuilds":  takeBuilds(builds, 6),
		"PackageCount":  len(pkgs),
		"DeletionCount": activeDeletions,
		"BuildCount":    len(builds),
		"RunningBuilds": runningBuilds,
		"DownloadCount": len(downloads),
		"Cooldown":      a.store.Cooldown().String(),
		"DefaultCreds":  defaultUsersSpec,
	})
}

func takeBuilds(in []BuildRecord, n int) []BuildRecord {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func (a *App) webDeletionsPage(w http.ResponseWriter, r *http.Request) {
	items := a.store.ListDeletions()
	renderPage(w, http.StatusOK, deletionsListPage, map[string]any{
		"Title":     "删除冷静期",
		"Active":    "deletions",
		"Deletions": items,
		"Packages":  a.store.ListPackages(false),
		"Cooldown":  a.store.Cooldown().String(),
	})
}

func (a *App) webDeletionDetailPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.store.GetDeletion(id)
	if err != nil {
		renderPage(w, http.StatusNotFound, errorPage, map[string]any{
			"Title":  "未找到删除申请",
			"Active": "deletions",
			"Error":  "找不到删除申请：" + id,
		})
		return
	}
	renderPage(w, http.StatusOK, deletionDetailPage, map[string]any{
		"Title":    "删除申请 " + d.ID,
		"Active":   "deletions",
		"D":        d,
		"Cooldown": a.store.Cooldown().String(),
	})
}

func (a *App) webBuildsPage(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("package")
	items := a.store.ListBuilds(pkg)
	renderPage(w, http.StatusOK, buildsPage, map[string]any{
		"Title":   "构建记录",
		"Active":  "builds",
		"Builds":  items,
		"Package": pkg,
	})
}

func (a *App) webDownloadsPage(w http.ResponseWriter, r *http.Request) {
	pkg := r.URL.Query().Get("package")
	items := a.store.ListDownloads(pkg)
	renderPage(w, http.StatusOK, downloadsPage, map[string]any{
		"Title":     "下载记录",
		"Active":    "downloads",
		"Downloads": items,
		"Package":   pkg,
	})
}

func (a *App) webPublishForm(w http.ResponseWriter, r *http.Request) {
	renderPage(w, http.StatusOK, publishPage, map[string]any{
		"Title":  "发布软件包",
		"Active": "publish",
	})
}

// publishNegotiate 让 /publish 同时服务浏览器表单（重定向/HTML 错误）与 API 客户端（JSON）。
func (a *App) publishNegotiate(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		a.webPublish(w, r)
		return
	}
	a.apiPublish(w, r)
}

func (a *App) webPackagePage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	pkg, err := a.store.GetPackage(name)
	if err != nil {
		renderPage(w, http.StatusNotFound, errorPage, map[string]any{
			"Title":  "未找到包",
			"Active": "home",
			"Error":  "找不到软件包：" + name,
		})
		return
	}
	refs := a.store.ReferencedBy(name)
	active, _ := a.store.ActiveDeletion(name, "")
	renderPage(w, http.StatusOK, packagePage, map[string]any{
		"Title":          name,
		"Active":         "home",
		"Pkg":            pkg,
		"ReferencedBy":   refs,
		"ActiveDeletion": active,
		"Downloads":      a.store.ListDownloads(name),
		"Builds":         a.store.ListBuilds(name),
	})
}

func (a *App) webVersionPage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.PathValue("version")
	v, err := a.store.GetVersion(name, version)
	if err != nil || v.Deleted {
		renderPage(w, http.StatusNotFound, errorPage, map[string]any{
			"Title":  "未找到版本",
			"Active": "home",
			"Error":  "找不到 " + name + "@" + version,
		})
		return
	}
	renderPage(w, http.StatusOK, versionPage, map[string]any{
		"Title":  name + "@" + v.Version,
		"Active": "home",
		"V":      v,
	})
}

func (a *App) webPublish(w http.ResponseWriter, r *http.Request) {
	in, err := readArtifactInput(r)
	if err != nil {
		renderPage(w, http.StatusBadRequest, publishPage, map[string]any{
			"Title":  "发布软件包",
			"Active": "publish",
			"Error":  "上传失败：" + err.Error(),
		})
		return
	}
	p := a.auth.principalOrAnonymous(r)
	v, err := a.store.Publish(PublishInput{
		Name: in.Name, Version: in.Version, Filename: in.Filename,
		Artifact: in.Artifact, UploadedBy: firstNonEmpty(p.User, "anonymous"),
	})
	if err != nil {
		renderPage(w, statusForError(err), publishPage, map[string]any{
			"Title":  "发布软件包",
			"Active": "publish",
			"Error":  "发布失败：" + err.Error(),
		})
		return
	}
	http.Redirect(w, r, "/packages/"+v.Name+"/"+v.Version+"?flash=发布成功", http.StatusSeeOther)
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, errUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, errForbidden), errors.Is(err, errSameConfirmer):
		return http.StatusForbidden
	case errors.Is(err, errNotFound), errors.Is(err, errPackageNotFound),
		errors.Is(err, errVersionNotFound), errors.Is(err, errRequestNotFound):
		return http.StatusNotFound
	case errors.Is(err, errNotDue), errors.Is(err, errReferenced),
		errors.Is(err, errAlreadyPending), errors.Is(err, errAlreadyPublished),
		errors.Is(err, errInvalidTransition):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}
