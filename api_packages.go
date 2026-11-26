package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

const maxArtifactBytes = 256 << 20

func (a *App) apiListPackages(w http.ResponseWriter, r *http.Request) {
	pkgs := a.store.ListPackages(r.URL.Query().Get("include_deleted") == "1" ||
		r.URL.Query().Get("all") == "1")
	writeJSON(w, http.StatusOK, map[string]any{
		"packages": pkgs,
		"items":    pkgs,
		"data":     pkgs,
		"count":    len(pkgs),
	})
}

func (a *App) apiGetPackage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	pkg, err := a.store.GetPackage(name)
	if err != nil {
		writeError(w, r, err)
		return
	}
	resp := map[string]any{
		"name":       pkg.Name,
		"created_at": pkg.CreatedAt,
		"versions":   pkg.Versions,
	}
	if refs := a.store.ReferencedBy(name); len(refs) > 0 {
		resp["referenced_by"] = refs
		resp["reference_count"] = len(refs)
	} else {
		resp["referenced_by"] = []Referrer{}
	}
	if active, err := a.store.ActiveDeletion(name, ""); err == nil {
		resp["active_deletion"] = active
		resp["deletion_pending"] = true
	} else {
		resp["deletion_pending"] = false
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *App) apiGetVersion(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.GetVersion(r.PathValue("name"), r.PathValue("version"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if v.Deleted {
		writeError(w, r, errVersionNotFound)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *App) apiManifest(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.GetVersion(r.PathValue("name"), r.PathValue("version"))
	if err != nil || v.Deleted {
		writeError(w, r, errVersionNotFound)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *App) apiReferencedBy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	refs := a.store.ReferencedBy(name)
	writeJSON(w, http.StatusOK, map[string]any{
		"package":       name,
		"referenced_by": refs,
		"items":         refs,
		"count":         len(refs),
	})
}

// artifactInput 承载解析出的发布参数。
type artifactInput struct {
	Name         string
	Version      string
	Filename     string
	Artifact     []byte
	Dependencies []Dependency
}

func (a *App) apiPublish(w http.ResponseWriter, r *http.Request) {
	// 发布默认允许匿名（便于 CI/夹具）；若配置了强制发布认证则校验 publisher 角色。
	p := a.auth.principalOrAnonymous(r)
	if truthy(firstNonEmpty(os.Getenv("PKG_REQUIRE_PUBLISH_AUTH"), os.Getenv("REQUIRE_PUBLISH_AUTH"))) {
		var err error
		p, err = a.auth.authenticate(r)
		if err != nil {
			writeError(w, r, err)
			return
		}
		if !p.canPublish() {
			writeError(w, r, errForbidden)
			return
		}
	}

	in, err := readArtifactInput(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if pathName := r.PathValue("name"); pathName != "" {
		in.Name = pathName
	}
	if pathVersion := r.PathValue("version"); pathVersion != "" {
		in.Version = pathVersion
	}

	v, err := a.store.Publish(PublishInput{
		Name:         in.Name,
		Version:      in.Version,
		Filename:     in.Filename,
		Artifact:     in.Artifact,
		Dependencies: in.Dependencies,
		UploadedBy:   firstNonEmpty(p.User, "anonymous"),
	})
	if err != nil {
		writeError(w, r, err)
		return
	}
	if acceptsHTMLForm(r) {
		http.Redirect(w, r, "/packages/"+v.Name+"/"+v.Version, http.StatusSeeOther)
		return
	}
	w.Header().Set("Location", "/api/packages/"+v.Name+"/versions/"+v.Version)
	writeJSON(w, http.StatusCreated, v)
}

func readArtifactInput(r *http.Request) (artifactInput, error) {
	in := artifactInput{}
	ct := r.Header.Get("Content-Type")

	if strings.Contains(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxArtifactBytes); err != nil {
			return in, errInvalidInput
		}
		in.Name = r.FormValue("name")
		in.Version = r.FormValue("version")
		file, header, err := r.FormFile("package")
		if err != nil {
			file, header, err = r.FormFile("file")
		}
		if err != nil {
			file, header, err = r.FormFile("artifact")
		}
		if err != nil {
			file, header, err = r.FormFile("tarball")
		}
		if err != nil {
			return in, errInvalidInput
		}
		defer file.Close()
		in.Filename = header.Filename
		raw, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes))
		if err != nil {
			return in, errInvalidInput
		}
		in.Artifact = raw
		return in, nil
	}

	if strings.Contains(ct, "application/json") {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			return in, errInvalidInput
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return in, errInvalidInput
		}
		in.Name, _ = body["name"].(string)
		in.Version, _ = body["version"].(string)
		if s, ok := body["package_name"].(string); ok {
			in.Name = s
		}
		in.Dependencies = parseDependenciesAny(body["dependencies"])
		if b64, ok := body["artifact_base64"].(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return in, errInvalidInput
			}
			in.Artifact = decoded
		} else if b64, ok := body["tar_base64"].(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return in, errInvalidInput
			}
			in.Artifact = decoded
		}
		return in, nil
	}

	// 原始 tar 字节流（PUT/POST），元数据来自路径、query 或请求头。
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxArtifactBytes))
	if err != nil {
		return in, errInvalidInput
	}
	in.Artifact = raw
	in.Name = firstNonEmpty(r.URL.Query().Get("name"), r.Header.Get("X-Package-Name"))
	in.Version = firstNonEmpty(r.URL.Query().Get("version"), r.Header.Get("X-Package-Version"))
	in.Filename = r.Header.Get("X-Artifact-Filename")
	return in, nil
}

func (a *App) apiDownload(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.PathValue("version")
	v, err := a.store.GetVersion(name, version)
	if err != nil || v.Deleted {
		writeError(w, r, errVersionNotFound)
		return
	}
	if !a.store.VerifyDigest(v) {
		writeError(w, r, errDigestMismatch)
		return
	}
	if active, err := a.store.ActiveDeletion(v.Name, ""); err == nil {
		w.Header().Set("X-Deletion-Pending", "true")
		w.Header().Set("X-Deletion-Request", active.ID)
		w.Header().Set("Warning", `299 - "package is pending deletion after cooldown"`)
	} else if active, err := a.store.ActiveDeletion(v.Name, v.Version); err == nil {
		w.Header().Set("X-Deletion-Pending", "true")
		w.Header().Set("X-Deletion-Request", active.ID)
		w.Header().Set("Warning", `299 - "version is pending deletion after cooldown"`)
	}
	p := a.auth.principalOrAnonymous(r)
	a.store.RecordDownload(DownloadRecord{
		Package:    v.Name,
		Name:       v.Name,
		Version:    v.Version,
		User:       p.User,
		RemoteAddr: remoteIP(r),
		UserAgent:  r.UserAgent(),
	})

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Content-Sha256", v.Digest)
	w.Header().Set("Digest", v.Digest)
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+sanitizeFilename(v.Name+"-"+v.Version)+`.tar"`)
	http.ServeFile(w, r, a.store.ObjectPath(v.Digest))
}

func (a *App) apiVerify(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.GetVersion(r.PathValue("name"), r.PathValue("version"))
	if err != nil || v.Deleted {
		writeError(w, r, errVersionNotFound)
		return
	}
	ok := a.store.VerifyDigest(v)
	writeJSON(w, http.StatusOK, map[string]any{
		"package":      v.Name,
		"version":      v.Version,
		"digest":       v.Digest,
		"digest_valid": ok,
		"verified":     ok,
	})
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	return strings.Trim(host, "[]")
}

func sanitizeFilename(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// parseDependenciesAny 解析 JSON 元数据中多种写法的 dependencies。
func parseDependenciesAny(v any) []Dependency {
	out := []Dependency{}
	switch deps := v.(type) {
	case map[string]any:
		for name, spec := range deps {
			c, _ := spec.(string)
			out = append(out, Dependency{Package: name, Constraint: c, Source: "api"})
		}
	case []any:
		for _, item := range deps {
			switch x := item.(type) {
			case string:
				if n, c := splitNameConstraint(x); n != "" {
					out = append(out, Dependency{Package: n, Constraint: c, Source: "api"})
				}
			case map[string]any:
				name, _ := firstString(x, "name", "package").(string)
				c, _ := firstString(x, "constraint", "version", "spec").(string)
				if name != "" {
					out = append(out, Dependency{Package: name, Constraint: c, Source: "api"})
				}
			}
		}
	}
	return out
}

func firstString(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return v
		}
	}
	return ""
}
