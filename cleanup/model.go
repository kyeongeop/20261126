package cleanup

import "time"

// Category is the result of checking one permission against the current data.
type Category string

const (
	CategoryFileDeleted    Category = "file_deleted"
	CategoryDirectoryMoved Category = "directory_moved"
	CategoryUserDisabled   Category = "user_disabled"
	CategoryValid          Category = "valid"
)

// Action describes the change needed to make the permission table consistent.
type Action string

const (
	ActionDeletePermission Action = "delete_permission"
	ActionUpdatePath       Action = "update_permission_path"
	ActionKeep             Action = "keep"
)

// ResourceKind identifies whether a shared target is a file or a directory.
type ResourceKind string

const (
	ResourceFile      ResourceKind = "file"
	ResourceDirectory ResourceKind = "directory"
)

// User is an account that can receive permissions.
type User struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Active bool   `json:"active"`
}

// Resource has a stable ID even when its path changes.
type Resource struct {
	ID   string       `json:"id"`
	Path string       `json:"path"`
	Kind ResourceKind `json:"kind"`
}

// Permission is a grant that snapshots the path at grant time.
type Permission struct {
	ID         string    `json:"id"`
	UserID     string    `json:"user_id"`
	ResourceID string    `json:"resource_id"`
	Path       string    `json:"path"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
}

// Database is the JSON-backed permission dataset.
type Database struct {
	Version     int                   `json:"version"`
	Revision    int64                 `json:"revision"`
	Users       []User                `json:"users"`
	Resources   []Resource            `json:"resources"`
	Permissions []Permission          `json:"permissions"`
	Previews    map[string]Preview    `json:"previews,omitempty"`
	Runs        map[string]CleanupRun `json:"runs,omitempty"`
}

// PreviewItem is a read-only classification of one existing permission.
type PreviewItem struct {
	ID             string       `json:"id"`
	PermissionID   string       `json:"permission_id"`
	UserID         string       `json:"user_id"`
	ResourceID     string       `json:"resource_id"`
	ResourceKind   ResourceKind `json:"resource_kind,omitempty"`
	PermissionPath string       `json:"permission_path"`
	CurrentPath    string       `json:"current_path,omitempty"`
	Category       Category     `json:"category"`
	Action         Action       `json:"action"`
	Reason         string       `json:"reason"`
}

// PreviewSummary gives stable machine-readable counts for all four categories.
type PreviewSummary struct {
	Total      int              `json:"total"`
	ByCategory map[Category]int `json:"by_category"`
	Changes    int              `json:"changes"`
}

// Preview is persisted so execution always refers to an explicit preview.
type Preview struct {
	ID            string         `json:"id"`
	StateRevision int64          `json:"state_revision"`
	CreatedAt     time.Time      `json:"created_at"`
	Items         []PreviewItem  `json:"items"`
	Summary       PreviewSummary `json:"summary"`
}

type ItemStatus string

const (
	ItemPending   ItemStatus = "pending"
	ItemApplying  ItemStatus = "applying"
	ItemApplied   ItemStatus = "applied"
	ItemFailed    ItemStatus = "failed"
	ItemUnchanged ItemStatus = "unchanged"
)

type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunCompleted RunStatus = "completed"
	RunPartial   RunStatus = "partial"
	RunFailed    RunStatus = "failed"
)

// PermissionChange is the before/after record written to the manifest.
type PermissionChange struct {
	Action string      `json:"action"`
	Before *Permission `json:"before,omitempty"`
	After  *Permission `json:"after,omitempty"`
}

// ManifestItem is also the durable checkpoint for one permission.
type ManifestItem struct {
	ID             string            `json:"id"`
	PermissionID   string            `json:"permission_id"`
	UserID         string            `json:"user_id"`
	ResourceID     string            `json:"resource_id"`
	ResourceKind   ResourceKind      `json:"resource_kind,omitempty"`
	Category       Category          `json:"category"`
	Action         Action            `json:"action"`
	PermissionPath string            `json:"permission_path"`
	CurrentPath    string            `json:"current_path,omitempty"`
	Reason         string            `json:"reason"`
	Status         ItemStatus        `json:"status"`
	Attempts       int               `json:"attempts"`
	LastError      string            `json:"last_error,omitempty"`
	Note           string            `json:"note,omitempty"`
	AppliedAt      *time.Time        `json:"applied_at,omitempty"`
	Change         *PermissionChange `json:"change,omitempty"`
}

// CleanupRun is the resumable manifest for one preview execution.
type CleanupRun struct {
	ID            string         `json:"id"`
	PreviewID     string         `json:"preview_id"`
	StateRevision int64          `json:"state_revision"`
	Status        RunStatus      `json:"status"`
	Round         int            `json:"round"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	CompletedAt   *time.Time     `json:"completed_at,omitempty"`
	Summary       PreviewSummary `json:"summary"`
	Items         []ManifestItem `json:"items"`
	ManifestPath  string         `json:"manifest_path,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
}
