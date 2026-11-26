package roleadmin

import (
	"errors"
	"net/http"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	service, err := NewDefaultService()
	if err != nil {
		t.Fatalf("NewDefaultService() error = %v", err)
	}
	return service
}

func deltaByAction(t *testing.T, deltas []PermissionDelta, action string) PermissionDelta {
	t.Helper()
	for _, delta := range deltas {
		if delta.Action == action {
			return delta
		}
	}
	t.Fatalf("permission %q not found in %#v", action, deltas)
	return PermissionDelta{}
}

func assertAPIError(t *testing.T, err error, status int, code string) {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.Status != status || apiErr.Code != code {
		t.Fatalf("error = %d %s, want %d %s", apiErr.Status, apiErr.Code, status, code)
	}
}

func TestPreviewShowsInheritedPermissionImpact(t *testing.T) {
	service := testService(t)
	preview, err := service.PreviewRoleChange("billing_admin", RoleUpdate{
		BaseVersion: 4,
		ParentRoleIDs: []string{
			"security_auditor",
			"support_agent",
		},
	}, "alice")
	if err != nil {
		t.Fatalf("PreviewRoleChange() error = %v", err)
	}

	if preview.Diff.RequiresApproval {
		t.Fatal("adding read-only inherited roles unexpectedly required approval")
	}
	if got := preview.Diff.Inherited.ParentsAdded; len(got) != 1 || got[0].ID != "security_auditor" {
		t.Fatalf("parents added = %#v, want security_auditor", got)
	}
	auditRead := deltaByAction(t, preview.Diff.Inherited.Added, "audit.read")
	if auditRead.Source != sourceInherited {
		t.Fatalf("audit.read source = %q, want inherited", auditRead.Source)
	}
	if len(auditRead.InheritedFrom) != 1 || auditRead.InheritedFrom[0] != "security_auditor" {
		t.Fatalf("audit.read inherited_from = %#v, want [security_auditor]", auditRead.InheritedFrom)
	}
	if preview.Diff.Summary.InheritedAdded != 2 {
		t.Fatalf("inherited added count = %d, want 2", preview.Diff.Summary.InheritedAdded)
	}
}

func TestPreviewShowsInheritedRemovalAndSensitiveApproval(t *testing.T) {
	service := testService(t)
	preview, err := service.PreviewRoleChange("billing_admin", RoleUpdate{
		BaseVersion:   4,
		ParentRoleIDs: []string{},
	}, "alice")
	if err != nil {
		t.Fatalf("PreviewRoleChange() error = %v", err)
	}

	if !preview.Diff.RequiresApproval {
		t.Fatal("removing inherited sensitive action did not require approval")
	}
	escalate := deltaByAction(t, preview.Diff.Inherited.Removed, "tickets.escalate")
	if escalate.Source != sourceInherited {
		t.Fatalf("tickets.escalate source = %q, want inherited", escalate.Source)
	}
	if len(preview.Diff.Inherited.ParentsRemoved) != 1 ||
		preview.Diff.Inherited.ParentsRemoved[0].ID != "support_agent" {
		t.Fatalf("parents removed = %#v", preview.Diff.Inherited.ParentsRemoved)
	}
	if len(preview.Diff.ApprovalItems) != 1 ||
		preview.Diff.ApprovalItems[0].ID != "removed:tickets.escalate" {
		t.Fatalf("approval items = %#v", preview.Diff.ApprovalItems)
	}
}

func TestNonSensitiveChangeIsAppliedImmediately(t *testing.T) {
	service := testService(t)
	request, err := service.SubmitRoleChange("billing_admin", RoleUpdate{
		BaseVersion:       4,
		DirectPermissions: []string{"billing.invoice.read", "reports.read"},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}
	if request.Status != ChangeApplied {
		t.Fatalf("status = %q, want applied", request.Status)
	}
	if request.Approval.Required {
		t.Fatal("non-sensitive change unexpectedly required approval")
	}

	role, err := service.GetRole("billing_admin")
	if err != nil {
		t.Fatalf("GetRole() error = %v", err)
	}
	if role.Version != 5 {
		t.Fatalf("version = %d, want 5", role.Version)
	}
	if !contains(role.DirectPermissions, "reports.read") {
		t.Fatalf("direct permissions = %#v, want reports.read", role.DirectPermissions)
	}
}

func TestSensitiveChangeRequiresAnotherAdminAndCanBePartiallyApproved(t *testing.T) {
	service := testService(t)
	request, err := service.SubmitRoleChange("billing_admin", RoleUpdate{
		BaseVersion: 4,
		DirectPermissions: []string{
			"billing.invoice.write",
			"reports.read",
			"users.delete",
		},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}
	if request.Status != ChangePending {
		t.Fatalf("status = %q, want pending_approval", request.Status)
	}
	if len(request.Approval.Items) != 2 {
		t.Fatalf("approval items = %#v, want two sensitive additions", request.Approval.Items)
	}

	_, err = service.DecideChangeRequest(request.ID, "alice", DecisionInput{
		Decision:        "approve",
		ApprovedActions: []string{"billing.invoice.write"},
	})
	assertAPIError(t, err, http.StatusForbidden, "second_admin_required")

	approved, err := service.DecideChangeRequest(request.ID, "bob", DecisionInput{
		Decision:        "approve",
		ApprovedActions: []string{"billing.invoice.write"},
		Comment:         "approve invoice write only",
	})
	if err != nil {
		t.Fatalf("DecideChangeRequest() error = %v", err)
	}
	if approved.Status != ChangeApplied || !approved.Approval.Partial {
		t.Fatalf("decision = %#v, want partial applied", approved.Approval)
	}
	if len(approved.Approval.ApprovedItemIDs) != 1 ||
		approved.Approval.ApprovedItemIDs[0] != "added:billing.invoice.write" {
		t.Fatalf("approved ids = %#v", approved.Approval.ApprovedItemIDs)
	}
	if len(approved.Approval.ApprovedActions) != 1 ||
		approved.Approval.ApprovedActions[0] != "billing.invoice.write" {
		t.Fatalf("approved actions = %#v", approved.Approval.ApprovedActions)
	}
	if len(approved.Approval.RejectedActions) != 1 ||
		approved.Approval.RejectedActions[0] != "users.delete" {
		t.Fatalf("rejected actions = %#v", approved.Approval.RejectedActions)
	}

	role, err := service.GetRole("billing_admin")
	if err != nil {
		t.Fatalf("GetRole() error = %v", err)
	}
	if role.Version != 5 {
		t.Fatalf("version = %d, want 5", role.Version)
	}
	if !contains(role.DirectPermissions, "billing.invoice.write") {
		t.Fatalf("approved permission missing: %#v", role.DirectPermissions)
	}
	if !contains(role.DirectPermissions, "reports.read") {
		t.Fatalf("non-sensitive permission was not applied: %#v", role.DirectPermissions)
	}
	if contains(role.DirectPermissions, "users.delete") {
		t.Fatalf("unapproved permission was applied: %#v", role.DirectPermissions)
	}
	if contains(role.DirectPermissions, "billing.invoice.read") {
		t.Fatalf("removed non-sensitive permission was retained: %#v", role.DirectPermissions)
	}
}

func TestPartialApprovalOfInheritedSensitiveGrantAddsExclusion(t *testing.T) {
	service := newInheritanceService(t)
	submitted, err := service.SubmitRoleChange("operator", RoleUpdate{
		BaseVersion:   1,
		ParentRoleIDs: []string{"high_parent"},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}
	if len(submitted.Approval.Items) != 2 {
		t.Fatalf("approval items = %#v, want two inherited sensitive grants", submitted.Approval.Items)
	}

	approved, err := service.DecideChangeRequest(submitted.ID, "bob", DecisionInput{
		Decision:        "approve",
		ApprovedItemIDs: []string{"added:roles.manage"},
	})
	if err != nil {
		t.Fatalf("DecideChangeRequest() error = %v", err)
	}
	if !approved.Approval.Partial {
		t.Fatal("approval was not marked partial")
	}

	role, err := service.GetRole("operator")
	if err != nil {
		t.Fatalf("GetRole() error = %v", err)
	}
	if !contains(role.ExcludedPermissions, "users.delete") {
		t.Fatalf("excluded permissions = %#v, want users.delete", role.ExcludedPermissions)
	}
	states, err := effectivePermissions(role.ID, service.roles)
	if err != nil {
		t.Fatalf("effectivePermissions() error = %v", err)
	}
	if _, granted := states["users.delete"]; granted {
		t.Fatal("unapproved inherited permission users.delete is effective")
	}
	if _, granted := states["roles.manage"]; !granted {
		t.Fatal("approved inherited permission roles.manage is not effective")
	}
	if _, granted := states["reports.read"]; !granted {
		t.Fatal("non-sensitive inherited permission reports.read is not effective")
	}
}

func TestPartialApprovalOfInheritedSensitiveRemovalKeepsPermission(t *testing.T) {
	service := newInheritanceService(t)
	if _, err := service.SubmitRoleChange("operator", RoleUpdate{
		BaseVersion:   1,
		ParentRoleIDs: []string{"high_parent"},
	}, "alice"); err != nil {
		t.Fatalf("add inherited parent: %v", err)
	}
	// Apply all sensitive additions so the role can be edited again.
	requests := service.ListChangeRequests()
	if len(requests) != 1 {
		t.Fatalf("change requests = %d, want 1", len(requests))
	}
	pending := requests[0]
	if pending.Status != ChangePending {
		t.Fatalf("adjustment status = %q, want pending_approval", pending.Status)
	}
	if _, err := service.DecideChangeRequest(pending.ID, "bob", DecisionInput{
		Decision:   "approve",
		ApproveAll: true,
	}); err != nil {
		t.Fatalf("approve inherited parent: %v", err)
	}

	removal, err := service.SubmitRoleChange("operator", RoleUpdate{
		BaseVersion:   2,
		ParentRoleIDs: []string{},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}
	if len(removal.Approval.Items) != 2 {
		t.Fatalf("approval items = %#v, want two inherited sensitive removals", removal.Approval.Items)
	}

	approved, err := service.DecideChangeRequest(removal.ID, "bob", DecisionInput{
		Decision:        "approve",
		ApprovedActions: []string{"roles.manage"},
	})
	if err != nil {
		t.Fatalf("DecideChangeRequest() error = %v", err)
	}
	if !approved.Approval.Partial {
		t.Fatal("removal approval was not marked partial")
	}

	role, err := service.GetRole("operator")
	if err != nil {
		t.Fatalf("GetRole() error = %v", err)
	}
	if !contains(role.DirectPermissions, "users.delete") {
		t.Fatalf("rejected removal was not retained: %#v", role.DirectPermissions)
	}
	if contains(role.DirectPermissions, "roles.manage") {
		t.Fatalf("approved removal was retained: %#v", role.DirectPermissions)
	}
}

func newInheritanceService(t *testing.T) *Service {
	t.Helper()
	service, err := NewService(Seed{
		Admins: []Admin{
			{ID: "alice", DisplayName: "Alice"},
			{ID: "bob", DisplayName: "Bob"},
		},
		SensitiveActions: []string{"roles.manage", "users.delete"},
		Roles: []Role{
			{
				ID:                "high_parent",
				Name:              "High Parent",
				Version:           1,
				DirectPermissions: []string{"reports.read", "roles.manage", "users.delete"},
			},
			{
				ID:                "operator",
				Name:              "Operator",
				Version:           1,
				DirectPermissions: []string{"tickets.read"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
