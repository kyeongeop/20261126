package main

import (
	"regexp"
	"strings"
	"time"
)

// 角色定义。权限从低到高：viewer < publisher < maintainer < admin。
const (
	RoleViewer     = "viewer"
	RolePublisher  = "publisher"
	RoleMaintainer = "maintainer"
	RoleAdmin      = "admin"
)

// 删除申请的生命周期状态。
const (
	// StatusPending 申请已提交，仍在删除冷静期内（待删除）。
	StatusPending = "pending"
	// StatusCooldownCompleted 冷静期已届满且引用检查通过，等待另一个有权限账号确认。
	StatusCooldownCompleted = "cooldown_completed"
	// StatusDeleted 已经第二人确认并执行删除（终态）。
	StatusDeleted = "deleted"
	// StatusWithdrawn 冷静期内被撤回（终态）。
	StatusWithdrawn = "withdrawn"
)

// 兼容外部测试/文档中可能使用的状态别名。
var statusAliases = map[string]string{
	"pending_deletion":     StatusPending,
	"in_cooldown":          StatusPending,
	"cooling_down":         StatusPending,
	"cooldown":             StatusPending,
	"waiting":              StatusPending,
	"ready":                StatusCooldownCompleted,
	"ready_to_confirm":     StatusCooldownCompleted,
	"pending_confirmation": StatusCooldownCompleted,
	"cooldown_complete":    StatusCooldownCompleted,
	"completed":            StatusDeleted,
	"confirmed":            StatusDeleted,
	"done":                 StatusDeleted,
	"cancelled":            StatusWithdrawn,
	"canceled":             StatusWithdrawn,
	"withdraw":             StatusWithdrawn,
}

func canonicalStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := statusAliases[s]; ok {
		return statusAliases[s]
	}
	switch s {
	case StatusPending, StatusCooldownCompleted, StatusDeleted, StatusWithdrawn:
		return s
	}
	return s
}

var (
	packageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
)

func validateNameVersion(name, version string) error {
	if !packageNamePattern.MatchString(name) {
		return errInvalidName
	}
	if version != "" && (!versionPattern.MatchString(version) || strings.Contains(version, "..")) {
		return errInvalidVersion
	}
	return nil
}

// Dependency 表示某个包版本对另一个包的依赖（引用）。
type Dependency struct {
	Package    string `json:"package"`
	Constraint string `json:"constraint,omitempty"`
	Source     string `json:"source,omitempty"`
}

// Version 是一个不可变的软件包版本记录。
type Version struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Digest       string       `json:"digest"`
	Size         int64        `json:"size"`
	Entries      int          `json:"entries"`
	Filename     string       `json:"filename,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
	UploadedBy   string       `json:"uploaded_by,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`

	Deleted           bool       `json:"deleted,omitempty"`
	DeletedAt         *time.Time `json:"deleted_at,omitempty"`
	DeletionRequestID string     `json:"deletion_request_id,omitempty"`
}

// Package 是同名版本的集合。
type Package struct {
	Name      string              `json:"name"`
	CreatedAt time.Time           `json:"created_at"`
	Versions  map[string]*Version `json:"versions"`
}

// DownloadRecord 记录一次软件包下载。
type DownloadRecord struct {
	ID         string    `json:"id"`
	Package    string    `json:"package"`
	Name       string    `json:"name,omitempty"`
	Version    string    `json:"version,omitempty"`
	User       string    `json:"user,omitempty"`
	RemoteAddr string    `json:"remote_addr,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	At         time.Time `json:"at"`
}

// BuildRecord 引用软件包的一次流水线构建。
type BuildRecord struct {
	ID         string     `json:"id"`
	Pipeline   string     `json:"pipeline"`
	Package    string     `json:"package"`
	Name       string     `json:"name,omitempty"`
	Version    string     `json:"version,omitempty"`
	Status     string     `json:"status"`
	Actor      string     `json:"actor,omitempty"`
	URL        string     `json:"url,omitempty"`
	Branch     string     `json:"branch,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Reference 表示一个“包引用另一个包”的关系（可由清单解析或手工登记）。
type Reference struct {
	ID          string    `json:"id"`
	FromPackage string    `json:"from_package"`
	FromVersion string    `json:"from_version,omitempty"`
	ToPackage   string    `json:"to_package"`
	Constraint  string    `json:"constraint,omitempty"`
	Source      string    `json:"source,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Referrer 描述一个引用了待删除包的活跃包版本。
type Referrer struct {
	Package    string `json:"package"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Constraint string `json:"constraint,omitempty"`
	Source     string `json:"source,omitempty"`
}
