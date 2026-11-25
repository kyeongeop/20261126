package main

import "time"

// ShareStatus 表示一条对外分享链接的当前状态。
type ShareStatus string

const (
	StatusActive  ShareStatus = "active"  // 有效，可访问、可撤销
	StatusRevoked ShareStatus = "revoked" // 已撤销
	StatusExpired ShareStatus = "expired" // 已过期
)

func (s ShareStatus) Valid() bool {
	switch s {
	case StatusActive, StatusRevoked, StatusExpired:
		return true
	}
	return false
}

// Share 是一条文件分享链接。撤销不会删除记录，只推进状态，
// 以便撤销后仍可追溯。
type Share struct {
	ID             string      `json:"id"`
	FileID         string      `json:"file_id"`
	FileName       string      `json:"file_name"`
	Directory      string      `json:"directory"`
	OwnerID        string      `json:"owner_id"`
	OwnerName      string      `json:"owner"`
	LinkToken      string      `json:"link_token"`
	Status         ShareStatus `json:"status"`
	CreatedAt      time.Time   `json:"created_at"`
	ExpiresAt      *time.Time  `json:"expires_at,omitempty"`
	RevokedAt      *time.Time  `json:"revoked_at,omitempty"`
	RevokeReason   string      `json:"revoke_reason,omitempty"`
	RevokeBatchID  string      `json:"revoke_batch_id,omitempty"`
	RevokeOperator string      `json:"revoke_operator,omitempty"`
}

// Filter 是批量撤销的筛选条件：负责人、目录、创建时间区间、链接状态。
// 零值字段表示不限制该维度。
type Filter struct {
	Owner       string     `json:"owner,omitempty"`
	Directory   string     `json:"directory,omitempty"`
	Recursive   bool       `json:"recursive"`
	CreatedFrom *time.Time `json:"created_from,omitempty"`
	CreatedTo   *time.Time `json:"created_to,omitempty"`
	Status      string     `json:"status,omitempty"`
}

// AuditTarget 固化撤销发生时每条链接的关键信息，避免后续数据变化影响审计可读性。
type AuditTarget struct {
	ShareID   string    `json:"share_id"`
	FileID    string    `json:"file_id"`
	FileName  string    `json:"file_name"`
	Directory string    `json:"directory"`
	OwnerName string    `json:"owner"`
	LinkToken string    `json:"link_token"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEvent 是一次批量撤销操作的不可变审计记录。
type AuditEvent struct {
	BatchID       string        `json:"batch_id"`
	Action        string        `json:"action"`
	Operator      string        `json:"operator"`
	Reason        string        `json:"reason"`
	Criteria      Filter        `json:"criteria"`
	MatchedLinks  int           `json:"matched_links"`
	RevokedLinks  int           `json:"revoked_links"`
	AffectedFiles int           `json:"affected_files"`
	ShareIDs      []string      `json:"share_ids"`
	FileIDs       []string      `json:"file_ids"`
	Targets       []AuditTarget `json:"targets"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Outcome       string        `json:"outcome"`
}

// dbData 是整个 JSON 数据文件的根结构。
type dbData struct {
	Version int          `json:"version"`
	Shares  []Share      `json:"shares"`
	Audits  []AuditEvent `json:"audits"`
}

// FileImpact 是预览中按文件聚合的受影响信息。
type FileImpact struct {
	FileID      string `json:"file_id"`
	FileName    string `json:"file_name"`
	Directory   string `json:"directory"`
	OwnerName   string `json:"owner"`
	ActiveLinks int    `json:"active_links"`
}

// PreviewInfo 是提交前的预览结果，重点给出受影响文件数。
type PreviewInfo struct {
	Criteria       Filter       `json:"criteria"`
	MatchedLinks   int          `json:"matched_links"`
	MatchedFiles   int          `json:"matched_files"`
	RevocableLinks int          `json:"revocable_links"`
	AffectedFiles  int          `json:"affected_files"`
	Files          []FileImpact `json:"files"`
	Items          []Share      `json:"items"`
}

// RevokeResult 是批量撤销成功后的结果。
type RevokeResult struct {
	BatchID       string     `json:"batch_id"`
	RevokedLinks  int        `json:"revoked_links"`
	AffectedFiles int        `json:"affected_files"`
	Reason        string     `json:"reason"`
	Operator      string     `json:"operator"`
	FinishedAt    time.Time  `json:"finished_at"`
	Audit         AuditEvent `json:"audit"`
}
