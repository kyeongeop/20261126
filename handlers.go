package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type publicationResponse struct {
	Release
	ServerVerification Verification `json:"server_verification"`
}

func (a *App) apiPublish(w http.ResponseWriter, r *http.Request) {
	a.handleAPIPublish(w, r, "", "")
}

func (a *App) apiPublishVersion(w http.ResponseWriter, r *http.Request) {
	a.handleAPIPublish(w, r, r.PathValue("name"), r.PathValue("version"))
}

func (a *App) handleAPIPublish(w http.ResponseWriter, r *http.Request, pathName, pathVersion string) {
	user, err := a.auth.authenticate(r)
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	input, err := readUpload(w, r)
	if err != nil {
		a.publishError(w, err)
		return
	}
	defer input.Close()

	name, version, err := resolveIdentity(pathName, pathVersion, input)
	if err != nil {
		a.publishError(w, err)
		return
	}
	if err := authorizePublish(user, input.RepairOf); err != nil {
		a.publishError(w, err)
		return
	}

	var repair *RepairInfo
	if input.RepairOf != "" {
		repair = &RepairInfo{OfVersion: input.RepairOf, Reason: repairReason(input.Reason)}
	}
	release, err := a.store.Publish(PublishRequest{
		Name:      name,
		Version:   version,
		Artifact:  input.Reader,
		Publisher: publisherRecord(user, r),
		Repair:    repair,
	})
	if err != nil {
		a.publishError(w, err)
		return
	}
	a.writePublication(w, release, http.StatusCreated)
}

func (a *App) apiRepair(w http.ResponseWriter, r *http.Request) {
	user, err := a.auth.requireRole(r, roleAdmin)
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	input, err := readUpload(w, r)
	if err != nil {
		a.publishError(w, err)
		return
	}
	defer input.Close()

	pathName, pathVersion := r.PathValue("name"), r.PathValue("version")
	if input.Name != "" && input.Name != pathName {
		a.publishError(w, errFieldMismatch)
		return
	}
	base, newVersion, err := resolveRepair(input, pathVersion)
	if err != nil {
		a.publishError(w, err)
		return
	}
	release, err := a.store.Publish(PublishRequest{
		Name:      pathName,
		Version:   newVersion,
		Artifact:  input.Reader,
		Publisher: publisherRecord(user, r),
		Repair:    &RepairInfo{OfVersion: base, Reason: repairReason(input.Reason)},
	})
	if err != nil {
		a.publishError(w, err)
		return
	}
	a.writePublication(w, release, http.StatusCreated)
}

func (a *App) uploadForm(w http.ResponseWriter, r *http.Request) {
	user, err := a.auth.requireRole(r, rolePublisher)
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	input, err := readUpload(w, r)
	if err != nil {
		a.renderFormError(w, "publish", statusForPublishError(err), user, "上传读取失败："+publicError(err))
		return
	}
	defer input.Close()
	if input.RepairOf != "" {
		a.renderFormError(w, "publish", http.StatusForbidden, user, "发布者只能发布新版本，修复版本必须由管理员创建。")
		return
	}
	name, version, err := resolveIdentity("", "", input)
	if err != nil {
		a.renderFormError(w, "publish", statusForPublishError(err), user, publicError(err))
		return
	}
	release, err := a.store.Publish(PublishRequest{
		Name:      name,
		Version:   version,
		Artifact:  input.Reader,
		Publisher: publisherRecord(user, r),
	})
	if err != nil {
		a.renderFormError(w, "publish", statusForPublishError(err), user, publicError(err))
		return
	}
	http.Redirect(w, r, releaseURL(release), http.StatusSeeOther)
}

func (a *App) repairForm(w http.ResponseWriter, r *http.Request) {
	user, err := a.auth.requireRole(r, roleAdmin)
	if err != nil {
		a.writeAuthError(w, r, err)
		return
	}
	input, err := readUpload(w, r)
	if err != nil {
		a.renderFormError(w, "repair", statusForPublishError(err), user, "上传读取失败："+publicError(err))
		return
	}
	defer input.Close()
	base, newVersion, err := resolveRepair(input, "")
	if err != nil {
		a.renderFormError(w, "repair", statusForPublishError(err), user, publicError(err))
		return
	}
	release, err := a.store.Publish(PublishRequest{
		Name:      input.Name,
		Version:   newVersion,
		Artifact:  input.Reader,
		Publisher: publisherRecord(user, r),
		Repair:    &RepairInfo{OfVersion: base, Reason: repairReason(input.Reason)},
	})
	if err != nil {
		a.renderFormError(w, "repair", statusForPublishError(err), user, publicError(err))
		return
	}
	http.Redirect(w, r, releaseURL(release), http.StatusSeeOther)
}

func authorizePublish(user principal, repairOf string) error {
	switch {
	case user.Role == rolePublisher && repairOf != "":
		return errForbidden
	case user.Role == roleAdmin && repairOf == "":
		return errAdminRepairOnly
	case user.Role != rolePublisher && user.Role != roleAdmin:
		return errForbidden
	default:
		return nil
	}
}

func resolveRepair(input uploadInput, pathVersion string) (string, string, error) {
	newVersion := input.NewVersion
	if input.Version != "" {
		if newVersion != "" && newVersion != input.Version {
			return "", "", errFieldMismatch
		}
		newVersion = input.Version
	}
	if newVersion == "" {
		newVersion = pathVersion
	}
	base := input.RepairOf
	if base == "" && pathVersion != "" && pathVersion != newVersion {
		base = pathVersion
	}
	if base == "" {
		return "", "", errRepairBase
	}
	if newVersion == "" {
		return "", "", errInvalidVersion
	}
	return base, newVersion, nil
}

func publisherRecord(user principal, r *http.Request) Publisher {
	return Publisher{
		User:       user.User,
		Role:       user.Role,
		RemoteAddr: r.RemoteAddr,
	}
}

func repairReason(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return "管理员修复版本"
	}
	return strings.TrimSpace(reason)
}

func (a *App) writePublication(w http.ResponseWriter, release Release, status int) {
	verification := a.store.Verify(release)
	w.Header().Set("Location", releaseURL(release))
	w.Header().Set("X-Signature-Verification", verificationStatus(verification))
	w.Header().Set("X-Content-SHA256", release.ContentDigest)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(publicationResponse{Release: release, ServerVerification: verification})
}

func (a *App) publishError(w http.ResponseWriter, err error) {
	status, code, message := classifyPublishError(err)
	httpError(w, status, code, message)
}

func (a *App) renderFormError(w http.ResponseWriter, templateName string, status int, user principal, message string) {
	a.render(w, templateName, status, pageData{
		Title:    "发布失败",
		Identity: &user,
		Error:    message,
	})
}

func classifyPublishError(err error) (int, string, string) {
	var maxBytes *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytes), errors.Is(err, errUploadTooLarge):
		return http.StatusRequestEntityTooLarge, "upload_too_large", "上传归档超过 128 MiB 限制。"
	case errors.Is(err, errVersionExists), errors.Is(err, os.ErrExist):
		return http.StatusConflict, "version_exists", "该包版本已发布，不可覆盖；请使用新的版本号。"
	case errors.Is(err, errRepairRequiresAdmin), errors.Is(err, errForbidden):
		return http.StatusForbidden, "repair_requires_admin", "修复版本只能由管理员创建。"
	case errors.Is(err, errAdminRepairOnly):
		return http.StatusForbidden, "admin_repair_only", "管理员只能创建修复版本，不能发布或改写普通版本。"
	case errors.Is(err, errRepairBaseNotFound):
		return http.StatusNotFound, "repair_target_not_found", "要修复的原版本不存在。"
	case errors.Is(err, errRepairBase), errors.Is(err, errInvalidVersion):
		return http.StatusBadRequest, "invalid_version", "版本号无效，或修复版本未指定被修复版本。"
	case errors.Is(err, errInvalidName):
		return http.StatusBadRequest, "invalid_name", "包名格式无效。"
	case errors.Is(err, errArtifactMissing):
		return http.StatusBadRequest, "artifact_required", "必须上传 tar 归档。"
	case errors.Is(err, errMalformedUpload):
		return http.StatusBadRequest, "malformed_upload", "上传请求格式无效。"
	case errors.Is(err, errFieldMismatch):
		return http.StatusBadRequest, "field_mismatch", "路径与表单中的包名或版本号不一致。"
	case errors.Is(err, errInvalidArchive):
		return http.StatusUnprocessableEntity, "invalid_archive", "归档不是有效的非空 tar 文件，或包含不安全路径。"
	default:
		return http.StatusInternalServerError, "publish_failed", "发布失败。"
	}
}

func statusForPublishError(err error) int {
	status, _, _ := classifyPublishError(err)
	return status
}

func publicError(err error) string {
	_, _, message := classifyPublishError(err)
	return message
}

func releaseURL(release Release) string {
	return "/packages/" + url.PathEscape(release.Name) + "/" + url.PathEscape(release.Version)
}
