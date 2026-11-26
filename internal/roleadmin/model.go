package roleadmin

import "time"

// Role is a versioned set of directly granted actions plus inherited roles.
// ExcludedPermissions is system-managed by partial approvals and overrides
// actions that would otherwise be granted directly or through inheritance.
type Role struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Version             int      `json:"version"`
	DirectPermissions   []string `json:"direct_permissions"`
	ParentRoleIDs       []string `json:"parent_role_ids"`
	ExcludedPermissions []string `json:"excluded_permissions,omitempty"`
}

type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// PermissionDelta describes one effective permission change. InheritedFrom is
// the role path that grants the action, beginning with the immediate parent.
type PermissionDelta struct {
	Action        string   `json:"action"`
	Sensitive     bool     `json:"sensitive"`
	Source        string   `json:"source"`
	InheritedFrom []string `json:"inherited_from,omitempty"`
}

type InheritedImpact struct {
	ParentsAdded   []RoleRef         `json:"parents_added"`
	ParentsRemoved []RoleRef         `json:"parents_removed"`
	Added          []PermissionDelta `json:"added"`
	Removed        []PermissionDelta `json:"removed"`
}

type DiffSummary struct {
	Added            int `json:"added"`
	Removed          int `json:"removed"`
	InheritedAdded   int `json:"inherited_added"`
	InheritedRemoved int `json:"inherited_removed"`
	Sensitive        int `json:"sensitive"`
}

type ApprovalItem struct {
	ID            string   `json:"id"`
	Operation     string   `json:"operation"`
	Action        string   `json:"action"`
	Sensitive     bool     `json:"sensitive"`
	Source        string   `json:"source"`
	InheritedFrom []string `json:"inherited_from,omitempty"`
}

type RoleDiff struct {
	RoleID           string            `json:"role_id"`
	BaseVersion      int               `json:"base_version"`
	ProposedVersion  int               `json:"proposed_version"`
	Added            []PermissionDelta `json:"added"`
	Removed          []PermissionDelta `json:"removed"`
	Inherited        InheritedImpact   `json:"inherited_impact"`
	Summary          DiffSummary       `json:"summary"`
	RequiresApproval bool              `json:"requires_approval"`
	ApprovalItems    []ApprovalItem    `json:"approval_items"`
}

type PreviewResult struct {
	RoleID       string   `json:"role_id"`
	Diff         RoleDiff `json:"diff"`
	ProposedRole Role     `json:"proposed_role"`
}

type ChangeStatus string

const (
	ChangePending  ChangeStatus = "pending_approval"
	ChangeApplied  ChangeStatus = "applied"
	ChangeRejected ChangeStatus = "rejected"
)

type ApprovalState struct {
	Required        bool           `json:"required"`
	Items           []ApprovalItem `json:"items"`
	ApprovedItemIDs []string       `json:"approved_item_ids,omitempty"`
	ApprovedActions []string       `json:"approved_actions,omitempty"`
	RejectedActions []string       `json:"rejected_actions,omitempty"`
	DecidedBy       string         `json:"decided_by,omitempty"`
	DecidedAt       *time.Time     `json:"decided_at,omitempty"`
	Comment         string         `json:"comment,omitempty"`
	Partial         bool           `json:"partial"`
}

type ChangeRequest struct {
	ID           string        `json:"id"`
	RoleID       string        `json:"role_id"`
	BaseVersion  int           `json:"base_version"`
	Status       ChangeStatus  `json:"status"`
	RequestedBy  string        `json:"requested_by"`
	RequestedAt  time.Time     `json:"requested_at"`
	Diff         RoleDiff      `json:"diff"`
	ProposedRole Role          `json:"proposed_role"`
	Approval     ApprovalState `json:"approval"`
	AppliedRole  *Role         `json:"applied_role,omitempty"`
}

type RoleUpdate struct {
	BaseVersion         int      `json:"base_version"`
	Name                string   `json:"name"`
	DirectPermissions   []string `json:"direct_permissions"`
	ParentRoleIDs       []string `json:"parent_role_ids"`
	ExcludedPermissions []string `json:"excluded_permissions"`
}

type DecisionInput struct {
	Decision        string   `json:"decision"`
	ApproveAll      bool     `json:"approve_all,omitempty"`
	ApprovedActions []string `json:"approved_actions,omitempty"`
	ApprovedItemIDs []string `json:"approved_item_ids,omitempty"`
	Comment         string   `json:"comment,omitempty"`
}

type Seed struct {
	Admins           []Admin  `json:"admins"`
	SensitiveActions []string `json:"sensitive_actions"`
	Roles            []Role   `json:"roles"`
}

type Admin struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}
