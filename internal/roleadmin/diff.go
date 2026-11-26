package roleadmin

import (
	"fmt"
	"sort"
)

const (
	sourceDirect             = "direct"
	sourceInherited          = "inherited"
	sourceDirectAndInherited = "direct+inherited"
)

func buildRoleDiff(
	base Role,
	target Role,
	roles map[string]Role,
	sensitiveActions map[string]bool,
) (RoleDiff, error) {
	baseStates, err := effectivePermissions(base.ID, roles)
	if err != nil {
		return RoleDiff{}, err
	}

	proposedRoles := cloneRoleMap(roles)
	proposedRoles[target.ID] = cloneRole(target)
	targetStates, err := effectivePermissions(target.ID, proposedRoles)
	if err != nil {
		return RoleDiff{}, err
	}

	added := make([]PermissionDelta, 0)
	inheritedAdded := make([]PermissionDelta, 0)
	for _, action := range sortedActions(targetStates) {
		if _, existed := baseStates[action]; existed {
			continue
		}
		delta := newPermissionDelta(action, targetStates[action], sensitiveActions[action])
		added = append(added, delta)
		if len(delta.InheritedFrom) > 0 {
			inheritedAdded = append(inheritedAdded, delta)
		}
	}

	removed := make([]PermissionDelta, 0)
	inheritedRemoved := make([]PermissionDelta, 0)
	for _, action := range sortedActions(baseStates) {
		if _, remains := targetStates[action]; remains {
			continue
		}
		delta := newPermissionDelta(action, baseStates[action], sensitiveActions[action])
		removed = append(removed, delta)
		if len(delta.InheritedFrom) > 0 {
			inheritedRemoved = append(inheritedRemoved, delta)
		}
	}

	parentsAdded, parentsRemoved := parentDiff(base, target, proposedRoles)
	approvalItems := make([]ApprovalItem, 0)
	for _, delta := range added {
		if delta.Sensitive {
			approvalItems = append(approvalItems, newApprovalItem("added", delta))
		}
	}
	for _, delta := range removed {
		if delta.Sensitive {
			approvalItems = append(approvalItems, newApprovalItem("removed", delta))
		}
	}

	diff := RoleDiff{
		RoleID:          base.ID,
		BaseVersion:     base.Version,
		ProposedVersion: target.Version,
		Added:           added,
		Removed:         removed,
		Inherited: InheritedImpact{
			ParentsAdded:   parentsAdded,
			ParentsRemoved: parentsRemoved,
			Added:          inheritedAdded,
			Removed:        inheritedRemoved,
		},
		Summary: DiffSummary{
			Added:            len(added),
			Removed:          len(removed),
			InheritedAdded:   len(inheritedAdded),
			InheritedRemoved: len(inheritedRemoved),
			Sensitive:        len(approvalItems),
		},
		RequiresApproval: len(approvalItems) > 0,
		ApprovalItems:    approvalItems,
	}
	return diff, nil
}

func newPermissionDelta(
	action string,
	state permissionState,
	sensitive bool,
) PermissionDelta {
	source := sourceInherited
	switch {
	case state.direct && len(state.inheritedFrom) > 0:
		source = sourceDirectAndInherited
	case state.direct:
		source = sourceDirect
	}
	return PermissionDelta{
		Action:        action,
		Sensitive:     sensitive,
		Source:        source,
		InheritedFrom: cloneStrings(state.inheritedFrom),
	}
}

func newApprovalItem(operation string, delta PermissionDelta) ApprovalItem {
	return ApprovalItem{
		ID:            fmt.Sprintf("%s:%s", operation, delta.Action),
		Operation:     operation,
		Action:        delta.Action,
		Sensitive:     delta.Sensitive,
		Source:        delta.Source,
		InheritedFrom: cloneStrings(delta.InheritedFrom),
	}
}

func parentDiff(base, target Role, roles map[string]Role) ([]RoleRef, []RoleRef) {
	baseParents := make(map[string]struct{}, len(base.ParentRoleIDs))
	for _, parentID := range base.ParentRoleIDs {
		baseParents[parentID] = struct{}{}
	}
	targetParents := make(map[string]struct{}, len(target.ParentRoleIDs))
	for _, parentID := range target.ParentRoleIDs {
		targetParents[parentID] = struct{}{}
	}

	added := make([]RoleRef, 0)
	for _, parentID := range target.ParentRoleIDs {
		if _, existed := baseParents[parentID]; !existed {
			added = append(added, roleRef(parentID, roles))
		}
	}
	removed := make([]RoleRef, 0)
	for _, parentID := range base.ParentRoleIDs {
		if _, remains := targetParents[parentID]; !remains {
			removed = append(removed, roleRef(parentID, roles))
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].ID < added[j].ID })
	sort.Slice(removed, func(i, j int) bool { return removed[i].ID < removed[j].ID })
	return added, removed
}

func roleRef(roleID string, roles map[string]Role) RoleRef {
	return RoleRef{ID: roleID, Name: roles[roleID].Name}
}
