package roleadmin

import (
	"net/http"
	"testing"
)

func TestRejectionLeavesRoleUntouchedAndCannotBeRepeated(t *testing.T) {
	service := testService(t)
	submitted, err := service.SubmitRoleChange("billing_admin", RoleUpdate{
		BaseVersion:       4,
		DirectPermissions: []string{"billing.invoice.read", "billing.invoice.write"},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}

	rejected, err := service.DecideChangeRequest(submitted.ID, "bob", DecisionInput{
		Decision: "reject",
		Comment:  "needs a separate billing review",
	})
	if err != nil {
		t.Fatalf("DecideChangeRequest() error = %v", err)
	}
	if rejected.Status != ChangeRejected || rejected.Approval.DecidedBy != "bob" {
		t.Fatalf("request = %#v, want rejection by bob", rejected)
	}
	if len(rejected.Approval.RejectedActions) != 1 ||
		rejected.Approval.RejectedActions[0] != "billing.invoice.write" {
		t.Fatalf("rejected actions = %#v", rejected.Approval.RejectedActions)
	}

	role, err := service.GetRole("billing_admin")
	if err != nil {
		t.Fatalf("GetRole() error = %v", err)
	}
	if role.Version != 4 || contains(role.DirectPermissions, "billing.invoice.write") {
		t.Fatalf("role changed after rejection: %#v", role)
	}
	_, err = service.DecideChangeRequest(submitted.ID, "carol", DecisionInput{
		Decision: "reject",
	})
	assertAPIError(t, err, http.StatusConflict, "request_already_decided")
}

func TestApprovalRejectsRequestsForStaleRoleVersions(t *testing.T) {
	service := testService(t)
	pending, err := service.SubmitRoleChange("billing_admin", RoleUpdate{
		BaseVersion:       4,
		DirectPermissions: []string{"billing.invoice.read", "billing.invoice.write"},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}
	applied, err := service.SubmitRoleChange("billing_admin", RoleUpdate{
		BaseVersion:       4,
		DirectPermissions: []string{"billing.invoice.read", "reports.read"},
	}, "bob")
	if err != nil {
		t.Fatalf("non-sensitive SubmitRoleChange() error = %v", err)
	}
	if applied.Status != ChangeApplied {
		t.Fatalf("non-sensitive status = %q, want applied", applied.Status)
	}

	_, err = service.DecideChangeRequest(pending.ID, "bob", DecisionInput{
		Decision:   "approve",
		ApproveAll: true,
	})
	assertAPIError(t, err, http.StatusConflict, "role_version_changed")
}

func TestApprovalSelectionIsValidatedBeforeApplying(t *testing.T) {
	service := testService(t)
	submitted, err := service.SubmitRoleChange("billing_admin", RoleUpdate{
		BaseVersion:       4,
		DirectPermissions: []string{"billing.invoice.read", "billing.invoice.write", "users.delete"},
	}, "alice")
	if err != nil {
		t.Fatalf("SubmitRoleChange() error = %v", err)
	}

	_, err = service.DecideChangeRequest(submitted.ID, "bob", DecisionInput{
		Decision:        "approve",
		ApprovedActions: []string{"reports.read"},
	})
	assertAPIError(t, err, http.StatusBadRequest, "unknown_approval_action")

	_, err = service.DecideChangeRequest(submitted.ID, "bob", DecisionInput{
		Decision:        "approve",
		ApproveAll:      true,
		ApprovedActions: []string{"billing.invoice.write"},
	})
	assertAPIError(t, err, http.StatusBadRequest, "invalid_decision")

	role, err := service.GetRole("billing_admin")
	if err != nil {
		t.Fatalf("GetRole() error = %v", err)
	}
	if role.Version != 4 {
		t.Fatalf("role version = %d after invalid decisions, want 4", role.Version)
	}

	approved, err := service.DecideChangeRequest(submitted.ID, "bob", DecisionInput{
		Decision:        "approve",
		ApprovedActions: []string{"billing.invoice.write"},
	})
	if err != nil {
		t.Fatalf("valid partial approval error = %v", err)
	}
	if !approved.Approval.Partial {
		t.Fatal("valid partial approval was not marked partial")
	}
}

func TestAccessChecksAndInheritanceValidation(t *testing.T) {
	service := testService(t)
	_, err := service.PreviewRoleChange("billing_admin", RoleUpdate{
		BaseVersion:   4,
		ParentRoleIDs: []string{"security_auditor"},
	}, "")
	assertAPIError(t, err, http.StatusUnauthorized, "admin_required")

	_, err = service.PreviewRoleChange("billing_admin", RoleUpdate{
		BaseVersion:   4,
		ParentRoleIDs: []string{"security_auditor"},
	}, "mallory")
	assertAPIError(t, err, http.StatusForbidden, "admin_required")

	_, err = service.PreviewRoleChange("base_support", RoleUpdate{
		BaseVersion:   1,
		ParentRoleIDs: []string{"support_agent"},
	}, "alice")
	assertAPIError(t, err, http.StatusUnprocessableEntity, "inheritance_cycle")

	_, err = service.PreviewRoleChange("billing_admin", RoleUpdate{
		BaseVersion:   4,
		ParentRoleIDs: []string{"missing_role"},
	}, "alice")
	assertAPIError(t, err, http.StatusUnprocessableEntity, "unknown_parent_role")
}
