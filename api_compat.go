package main

import (
	"errors"
	"net/http"
)

// apiDeletePackageResource 让 REST 风格的 DELETE 包/版本转为“发起删除冷静期申请”，而不是立即删除。
func (a *App) apiDeletePackageResource(w http.ResponseWriter, r *http.Request) {
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
	name := r.PathValue("name")
	version := r.PathValue("version")
	if version == "" && f != nil {
		version = f.getString("version")
	}
	reason := ""
	cooldownSecs := (*int64)(nil)
	if f != nil {
		reason = f.getString("reason", "comment")
		if secs, ok := f.getInt64("cooldown_seconds", "ttl_seconds"); ok {
			cooldownSecs = &secs
		}
	}
	d, err := a.store.CreateDeletion(CreateDeletionInput{
		Name: name, Version: version, Reason: reason,
		RequestedBy: p.User, RequesterRole: p.Role, CooldownSeconds: cooldownSecs,
	})
	if err != nil {
		if d != nil && errors.Is(err, errAlreadyPending) {
			w.Header().Set("Location", "/api/deletion-requests/"+d.ID)
			writeJSON(w, http.StatusOK, d)
			return
		}
		writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/deletion-requests/"+d.ID)
	writeJSON(w, http.StatusAccepted, d)
}

// apiDispatchDeletion 支持 PATCH/POST 资源根并通过 action 或 status 字段驱动状态流转。
func (a *App) apiDispatchDeletion(w http.ResponseWriter, r *http.Request) {
	f, _ := decodeFields(r)
	id := r.PathValue("id")
	action := ""
	status := ""
	if f != nil {
		action = f.getString("action", "op", "do")
		status = canonicalStatus(f.getString("status", "state"))
		if id == "" {
			id = f.getString("id", "request_id")
		}
	}

	switch action {
	case "withdraw", "cancel", "revoke", "recall":
		a.dispatchWithdraw(w, r, f, id)
	case "complete", "complete-cooldown", "expire", "advance", "mark-expired", "finish-cooldown":
		a.dispatchComplete(w, r, f, id)
	case "confirm", "approve", "accept", "second-confirm":
		a.dispatchConfirm(w, r, f, id)
	default:
		switch status {
		case StatusWithdrawn:
			a.dispatchWithdraw(w, r, f, id)
		case StatusCooldownCompleted:
			a.dispatchComplete(w, r, f, id)
		case StatusDeleted:
			a.dispatchConfirm(w, r, f, id)
		default:
			d, err := a.store.GetDeletion(id)
			if err != nil {
				writeError(w, r, err)
				return
			}
			writeJSON(w, http.StatusOK, d)
		}
	}
}

func (a *App) dispatchWithdraw(w http.ResponseWriter, r *http.Request, f *fields, id string) {
	p, err := a.auth.principalFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canRequestDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	d, err := a.store.WithdrawDeletion(id, p.User)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) dispatchComplete(w http.ResponseWriter, r *http.Request, f *fields, id string) {
	p, err := a.auth.principalFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canRequestDeletion() {
		writeError(w, r, errForbidden)
		return
	}
	d, err := a.store.CompleteCooldown(id)
	if err != nil {
		writeActionError(w, r, d, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *App) dispatchConfirm(w http.ResponseWriter, r *http.Request, f *fields, id string) {
	p, err := a.auth.confirmerFromFields(r, f)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if !p.canConfirmDeletion() {
		writeError(w, r, errForbidden)
		return
	}
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

func (a *App) apiDeletionImpact(w http.ResponseWriter, r *http.Request) {
	d, err := a.store.GetDeletion(r.PathValue("id"))
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d.Impact)
}

func (a *App) apiPackageImpact(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version := r.URL.Query().Get("version")
	impact := a.store.Impact(name, version)
	writeJSON(w, http.StatusOK, impact)
}
