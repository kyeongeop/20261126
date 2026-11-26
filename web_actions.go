package main

import (
	"errors"
	"net/http"
	"strconv"
)

func (a *App) webCreate(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticateWeb(w, r)
	if !ok {
		return
	}
	if !p.canRequestDeletion() {
		renderPage(w, http.StatusForbidden, errorPage, map[string]any{
			"Title": "无权限", "Active": "deletions",
			"Error": "只有维护者或管理员可以发起删除申请。",
		})
		return
	}
	_ = r.ParseForm()
	input := CreateDeletionInput{
		Name:          r.FormValue("name"),
		Version:       r.FormValue("version"),
		Reason:        r.FormValue("reason"),
		RequestedBy:   p.User,
		RequesterRole: p.Role,
	}
	if raw := r.FormValue("cooldown_seconds"); raw != "" {
		if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
			input.CooldownSeconds = &secs
		}
	}
	d, err := a.store.CreateDeletion(input)
	if err != nil {
		id := ""
		if d != nil {
			id = d.ID
		}
		a.renderActionError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/deletions/"+d.ID+"?flash=已进入删除冷静期", http.StatusSeeOther)
}

func (a *App) webWithdraw(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticateWeb(w, r)
	if !ok {
		return
	}
	if !p.canRequestDeletion() {
		renderPage(w, http.StatusForbidden, errorPage, map[string]any{
			"Title": "无权限", "Active": "deletions", "Error": "当前角色无权撤回删除申请。",
		})
		return
	}
	id := r.PathValue("id")
	if _, err := a.store.WithdrawDeletion(id, p.User); err != nil {
		a.renderActionError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/deletions/"+id+"?flash=已撤回，软件包恢复可用", http.StatusSeeOther)
}

func (a *App) webComplete(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticateWeb(w, r)
	if !ok {
		return
	}
	if !p.canRequestDeletion() {
		renderPage(w, http.StatusForbidden, errorPage, map[string]any{
			"Title": "无权限", "Active": "deletions", "Error": "需要维护者或管理员角色。",
		})
		return
	}
	id := r.PathValue("id")
	if _, err := a.store.CompleteCooldown(id); err != nil {
		a.renderActionError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/deletions/"+id+"?flash=冷静期已完成，等待另一个管理员确认", http.StatusSeeOther)
}

func (a *App) webConfirm(w http.ResponseWriter, r *http.Request) {
	p, ok := a.authenticateWeb(w, r)
	if !ok {
		return
	}
	if !p.canConfirmDeletion() {
		renderPage(w, http.StatusForbidden, errorPage, map[string]any{
			"Title": "无确认权限", "Active": "deletions",
			"Error": "只有维护者或管理员等有权限的账号可以执行第二人确认。",
		})
		return
	}
	id := r.PathValue("id")
	current, gerr := a.store.GetDeletion(id)
	if gerr != nil {
		a.renderActionError(w, r, id, gerr)
		return
	}
	if current.Status != StatusDeleted && p.User == current.RequestedBy {
		a.renderActionError(w, r, id, errSameConfirmer)
		return
	}
	if _, err := a.store.ConfirmDeletion(id, p.User); err != nil {
		a.renderActionError(w, r, id, err)
		return
	}
	http.Redirect(w, r, "/deletions/"+id+"?flash=第二人确认完成，软件包已删除", http.StatusSeeOther)
}

func (a *App) renderActionError(w http.ResponseWriter, r *http.Request, id string, err error) {
	d, _ := a.store.GetDeletion(id)
	status := statusForError(err)
	data := map[string]any{
		"Title":  "操作未成功",
		"Active": "deletions",
		"Error":  actionErrorMessage(err),
	}
	page := errorPage
	if d != nil {
		data["D"] = d
		data["Title"] = "删除申请 " + d.ID
		page = deletionDetailPage
	}
	renderPage(w, status, page, data)
}

func actionErrorMessage(err error) string {
	switch {
	case errors.Is(err, errNotDue):
		return "冷静期尚未届满，暂时不能完成或确认。"
	case errors.Is(err, errReferenced):
		return "该包仍被其他活跃包引用，不能进入冷静期完成/删除状态。请先解除引用。"
	case errors.Is(err, errSameConfirmer):
		return "职责分离要求：必须由不同于申请人的另一个管理员账号确认。"
	case errors.Is(err, errAlreadyPending):
		return "该目标已经存在进行中的删除申请。"
	case errors.Is(err, errInvalidTransition):
		return "当前状态不允许执行该操作。"
	case errors.Is(err, errRequestNotFound):
		return "找不到对应的删除申请。"
	default:
		return err.Error()
	}
}
