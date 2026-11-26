package main

import "time"

// Impact 汇总一次删除可能影响到的下载、构建与引用方。
type Impact struct {
	Downloads            []DownloadRecord `json:"downloads"`
	Builds               []BuildRecord    `json:"builds"`
	ReferencedBy         []Referrer       `json:"referenced_by"`
	DownloadCount        int              `json:"download_count"`
	BuildCount           int              `json:"build_count"`
	ActiveBuildCount     int              `json:"active_build_count"`
	InProgressBuildCount int              `json:"in_progress_build_count,omitempty"`
	ReferrerCount        int              `json:"referrer_count"`
}

// DeletionRequest 表示一次“删除冷静期”申请及其完整审批轨迹。
type DeletionRequest struct {
	ID           string `json:"id"`
	RequestID    string `json:"request_id,omitempty"`
	Number       int    `json:"number"`
	PackageName  string `json:"package_name"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Target       string `json:"target"`
	Reason       string `json:"reason,omitempty"`
	Status       string `json:"status"`
	State        string `json:"state,omitempty"`
	StoredStatus string `json:"stored_status,omitempty"`
	StatusLabel  string `json:"status_label"`

	RequestedBy   string    `json:"requested_by"`
	Requester     string    `json:"requester"`
	CreatedBy     string    `json:"created_by,omitempty"`
	RequesterRole string    `json:"requester_role,omitempty"`
	CreatedAt     time.Time `json:"created_at"`

	CooldownSeconds  int64     `json:"cooldown_seconds"`
	ExpiresAt        time.Time `json:"expires_at"`
	DueAt            time.Time `json:"due_at,omitempty"`
	Due              bool      `json:"due"`
	Expired          bool      `json:"expired"`
	SecondsRemaining int64     `json:"seconds_remaining"`
	ExpiresInSeconds int64     `json:"expires_in_seconds,omitempty"`

	CooldownCompletedAt *time.Time `json:"cooldown_completed_at,omitempty"`
	ReadyAt             *time.Time `json:"ready_at,omitempty"`

	ConfirmedBy string     `json:"confirmed_by,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`

	WithdrawnBy string     `json:"withdrawn_by,omitempty"`
	WithdrawnAt *time.Time `json:"withdrawn_at,omitempty"`

	DeletedAt *time.Time `json:"deleted_at,omitempty"`

	Blocked      bool       `json:"blocked"`
	BlockCode    string     `json:"block_code,omitempty"`
	BlockReasons []string   `json:"block_reasons,omitempty"`
	ReferencedBy []Referrer `json:"referenced_by"`

	AffectedDownloads []DownloadRecord `json:"affected_downloads"`
	AffectedBuilds    []BuildRecord    `json:"affected_builds"`
	Downloads         []DownloadRecord `json:"downloads,omitempty"`
	Builds            []BuildRecord    `json:"builds,omitempty"`
	ImpactedDownloads []DownloadRecord `json:"impacted_downloads,omitempty"`
	ImpactedBuilds    []BuildRecord    `json:"impacted_builds,omitempty"`
	Impact            Impact           `json:"impact"`

	CanWithdraw bool `json:"can_withdraw"`
	CanComplete bool `json:"can_complete"`
	CanConfirm  bool `json:"can_confirm"`

	// Viewer 是当前认证用户视角的附加权限信息（不参与状态机）。
	Viewer           any  `json:"viewer,omitempty"`
	ViewerCanConfirm bool `json:"viewer_can_confirm,omitempty"`
}

// statusLabels 给出中文状态文案，方便页面与人工验收。
var statusLabels = map[string]string{
	StatusPending:           "待删除 · 冷静期中",
	StatusCooldownCompleted: "冷静期已满 · 待第二人确认",
	StatusDeleted:           "已删除",
	StatusWithdrawn:         "已撤回",
}

func labelFor(status string) string {
	if label, ok := statusLabels[status]; ok {
		return label
	}
	return status
}
