package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *App) apiListDeletions(w http.ResponseWriter, r *http.Request) {
	items := a.store.ListDeletions()
	writeJSON(w, http.StatusOK, map[string]any{
		"deletion_requests": items,
		"items":             items,
		"data":              items,
		"count":             len(items),
		"total":             len(items),
	})
}

func (a *App) apiListForPackage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	all := a.store.ListDeletions()
	items := []*DeletionRequest{}
	for _, d := range all {
		if d.PackageName == name {
			items = append(items, d)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deletion_requests": items,
		"items":             items,
		"data":              items,
		"count":             len(items),
	})
}

func (a *App) apiGetDeletion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	d, err := a.store.GetDeletion(id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	a.withViewerPermissions(r, d)
	writeJSON(w, http.StatusOK, d)
}

func (a *App) apiActiveForPackage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	d, err := a.store.ActiveDeletion(name, version)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) apiCreateDeletion(w http.ResponseWriter, r *http.Request) {
	f, err := decodeFields(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	p, err := a.auth.principalFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canRequestDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	name := f.getString("name", "package_name", "package", "pkg", "packageName")
	if pathName := r.PathValue("name"); pathName != "" {
		name = pathName
	}
	version := f.getString("version", "version_range", "ver")
	reason := f.getString("reason", "comment", "note", "description")

	input := CreateDeletionInput{
		Name:          name,
		Version:       version,
		Reason:        reason,
		RequestedBy:   p.User,
		RequesterRole: p.Role,
	}
	if secs, ok := f.getInt64("cooldown_seconds", "cooldown_secs", "cooldown_period_seconds",
		"cooling_period_seconds", "grace_seconds", "ttl_seconds", "delay_seconds", "wait_seconds"); ok {
		input.CooldownSeconds = &secs
	}
	if raw := f.getString("cooldown", "cooldown_duration", "cooling_period"); raw != "" {
		if d, perr := time.ParseDuration(raw); perr == nil {
			input.Cooldown = d
			input.CooldownSeconds = nil
		} else if secs, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64); perr == nil {
			input.CooldownSeconds = &secs
		}
	}
	// 只有管理员可以为单个申请缩短/覆盖冷静期，避免申请人架空冷静期。
	if input.CooldownSeconds != nil || input.Cooldown > 0 {
		if !p.canConfirmDeletion() {
			input.CooldownSeconds = nil
			input.Cooldown = 0
		}
	}

	d, err := a.store.CreateDeletion(input)
	if err != nil {
		if d != nil && errors.Is(err, errAlreadyPending) {
			w.Header().Set("Location", "/api/deletion-requests/"+d.ID)
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":            err.Error(),
				"message":          err.Error(),
				"code":             errorCode(err),
				"deletion_request": d,
				"id":               d.ID,
			})
			return
		}
		writeError(w, r, err)
		return
	}
	a.withViewerPermissions(r, d)
	w.Header().Set("Location", "/api/deletion-requests/"+d.ID)
	if acceptsHTMLForm(r) {
		http.Redirect(w, r, "/deletions/"+d.ID, http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

func (a *App) apiWithdrawDeletion(w http.ResponseWriter, r *http.Request) {
	f, _ := decodeFields(r)
	p, err := a.auth.principalFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canRequestDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	id := r.PathValue("id")
	if id == "" && f != nil {
		id = f.getString("id", "request_id")
	}
	d, err := a.store.WithdrawDeletion(id, p.User)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	if acceptsHTMLForm(r) {
		http.Redirect(w, r, "/deletions/"+d.ID, http.StatusSeeOther)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) apiWithdrawByPackage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	if f, err := decodeFields(r); err == nil {
		if v := f.getString("version"); v != "" {
			version = v
		}
	}
	active, err := a.store.ActiveDeletion(name, version)
	if err != nil {
		writeError(w, r, err)
		return
	}
	r.SetPathValue("id", active.ID)
	a.apiWithdrawDeletion(w, r)
}

func (a *App) apiCompleteDeletion(w http.ResponseWriter, r *http.Request) {
	f, _ := decodeFields(r)
	p, err := a.auth.principalFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canRequestDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	id := r.PathValue("id")
	d, err := a.store.CompleteCooldown(id)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) apiCompleteByPackage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	active, err := a.store.ActiveDeletion(name, version)
	if err != nil {
		writeError(w, r, err)
		return
	}
	d, err := a.store.CompleteCooldown(active.ID)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) apiConfirmDeletion(w http.ResponseWriter, r *http.Request) {
	f, _ := decodeFields(r)
	p, err := a.auth.confirmerFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canConfirmDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	id := r.PathValue("id")

	current, err := a.store.GetDeletion(id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if current.Status != StatusDeleted && p.User == current.RequestedBy {
		writeError(w, r, errSameConfirmer)
		return
	}
	d, err := a.store.ConfirmDeletion(id, p.User)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) apiConfirmByPackage(w http.ResponseWriter, r *http.Request) {
	f, _ := decodeFields(r)
	p, err := a.auth.confirmerFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canConfirmDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	active, err := a.store.ActiveDeletion(name, version)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if p.User == active.RequestedBy {
		writeError(w, r, errSameConfirmer)
		return
	}
	d, err := a.store.ConfirmDeletion(active.ID, p.User)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// withViewerPermissions 追加“当前查看者是否可执行确认”等身份相关标记。
func (a *App) withViewerPermissions(r *http.Request, d *DeletionRequest) {
	p := a.auth.principalOrAnonymous(r)
	viewer := map[string]any{
		"authenticated": p.User != "",
		"user":          p.User,
		"role":          p.Role,
	}
	due := d.Status == StatusCooldownCompleted || (d.Status == StatusPending && d.Due)
	viewer["can_withdraw"] = p.canRequestDeletion() && d.CanWithdraw
	viewer["can_complete"] = p.canRequestDeletion() && d.CanComplete
	viewer["can_confirm"] = p.canConfirmDeletion() && due && !d.Blocked && p.User != d.RequestedBy
	viewer["must_be_different_account"] = p.User == d.RequestedBy && p.User != ""
	d.Viewer = viewer
	if can, ok := viewer["can_confirm"].(bool); ok {
		d.ViewerCanConfirm = can
	}
}

func writeActionError(w http.ResponseWriter, r *http.Request, d *DeletionRequest, err error) {
	status := http.StatusConflict
	switch {
	case errors.Is(err, errUnauthorized):
		status = http.StatusUnauthorized
	case errors.Is(err, errForbidden), errors.Is(err, errSameConfirmer):
		status = http.StatusForbidden
	case errors.Is(err, errNotFound), errors.Is(err, errRequestNotFound):
		status = http.StatusNotFound
	case errors.Is(err, errInvalidInput):
		status = http.StatusBadRequest
	}
	body := map[string]any{
		"error":   err.Error(),
		"message": err.Error(),
		"code":    errorCode(err),
		"status":  status,
	}
	if d != nil {
		body["deletion_request"] = d
		body["id"] = d.ID
	}
	writeJSON(w, status, body)
}

func acceptsHTMLForm(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return false
	}
	if r.FormValue("format") == "json" {
		return false
	}
	return wantsHTML(r)
}

func decodeFieldsQuiet(r *http.Request) *fields {
	f, _ := decodeFields(r)
	return f
}
