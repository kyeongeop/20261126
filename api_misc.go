package main

import (
	"net/http"
	"time"
)

func (a *App) apiListBuilds(w http.ResponseWriter, r *http.Request) {
	pkg := firstNonEmpty(r.PathValue("name"),
		r.URL.Query().Get("package"), r.URL.Query().Get("package_name"), r.URL.Query().Get("name"))
	items := a.store.ListBuilds(pkg)
	writeJSON(w, http.StatusOK, map[string]any{
		"builds": items,
		"items":  items,
		"data":   items,
		"count":  len(items),
	})
}

func (a *App) apiCreateBuild(w http.ResponseWriter, r *http.Request) {
	f, err := decodeFields(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	p := a.auth.principalOrAnonymous(r)
	b := BuildRecord{
		Pipeline: f.getString("pipeline", "pipeline_name", "workflow", "job", "ci_job"),
		Package:  f.getString("package", "package_name", "name", "pkg"),
		Version:  f.getString("version", "package_version", "ver"),
		Status:   f.getString("status", "state"),
		Actor:    firstNonEmpty(f.getString("actor", "user", "triggered_by"), p.User),
		URL:      f.getString("url", "html_url", "link"),
		Branch:   f.getString("branch", "ref", "git_branch"),
	}
	if b.Package == "" {
		b.Package = r.PathValue("name")
	}
	if b.Package == "" {
		writeError(w, r, errInvalidInput)
		return
	}
	if b.Pipeline == "" {
		b.Pipeline = "pipeline-" + b.Package
	}
	if b.Status == "" {
		b.Status = "running"
	}
	if raw := f.getString("started_at"); raw != "" {
		if t, perr := time.Parse(time.RFC3339, raw); perr == nil {
			b.StartedAt = t
		}
	}
	created := a.store.AddBuild(b)
	if acceptsHTMLForm(r) {
		http.Redirect(w, r, "/builds", http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (a *App) apiListDownloads(w http.ResponseWriter, r *http.Request) {
	pkg := firstNonEmpty(r.PathValue("name"),
		r.URL.Query().Get("package"), r.URL.Query().Get("package_name"), r.URL.Query().Get("name"))
	items := a.store.ListDownloads(pkg)
	writeJSON(w, http.StatusOK, map[string]any{
		"downloads": items,
		"items":     items,
		"data":      items,
		"count":     len(items),
	})
}

func (a *App) apiCreateDownload(w http.ResponseWriter, r *http.Request) {
	f, err := decodeFields(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	p := a.auth.principalOrAnonymous(r)
	rec := DownloadRecord{
		Package:    f.getString("package", "package_name", "name", "pkg"),
		Version:    f.getString("version", "package_version", "ver"),
		User:       firstNonEmpty(f.getString("user", "username", "actor"), p.User),
		RemoteAddr: remoteIP(r),
		UserAgent:  r.UserAgent(),
	}
	if rec.Package == "" {
		rec.Package = r.PathValue("name")
	}
	if rec.Package == "" {
		writeError(w, r, errInvalidInput)
		return
	}
	created := a.store.RecordDownload(rec)
	writeJSON(w, http.StatusCreated, created)
}

func (a *App) apiListReferences(w http.ResponseWriter, r *http.Request) {
	// 引用关系同时包含手工登记与清单解析；这里返回手工登记 + 全量推导视图。
	target := r.URL.Query().Get("to_package")
	name := r.URL.Query().Get("package")
	if target == "" {
		target = name
	}
	if target != "" {
		refs := a.store.ReferencedBy(target)
		writeJSON(w, http.StatusOK, map[string]any{
			"to_package":    target,
			"referenced_by": refs,
			"items":         refs,
			"count":         len(refs),
		})
		return
	}
	all := a.store.AllReferences()
	writeJSON(w, http.StatusOK, map[string]any{
		"references": all,
		"items":      all,
		"data":       all,
		"count":      len(all),
	})
}

func (a *App) apiCreateReference(w http.ResponseWriter, r *http.Request) {
	f, err := decodeFields(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	p := a.auth.principalOrAnonymous(r)
	ref := Reference{
		FromPackage: f.getString("from_package", "from", "source_package", "package", "name"),
		FromVersion: f.getString("from_version", "source_version"),
		ToPackage:   f.getString("to_package", "to", "target_package", "dependency", "depends_on"),
		Constraint:  f.getString("constraint", "version_constraint", "spec"),
		Source:      firstNonEmpty(f.getString("source"), "api"),
		CreatedBy:   p.User,
	}
	// 支持 {"from_package":"a","dependencies":["b","c"]} 的批量写法。
	if ref.ToPackage == "" {
		if deps, ok := f.values["dependencies"].([]any); ok && ref.FromPackage != "" {
			created := []Reference{}
			for _, item := range deps {
				name, _ := item.(string)
				if n, c := splitNameConstraint(name); n != "" {
					created = append(created, a.store.AddReference(Reference{
						FromPackage: ref.FromPackage,
						ToPackage:   n,
						Constraint:  c,
						Source:      "api",
						CreatedBy:   p.User,
					}))
				}
			}
			writeJSON(w, http.StatusCreated, map[string]any{"references": created, "count": len(created)})
			return
		}
	}
	if ref.FromPackage == "" || ref.ToPackage == "" {
		writeError(w, r, errInvalidInput)
		return
	}
	created := a.store.AddReference(ref)
	writeJSON(w, http.StatusCreated, created)
}
