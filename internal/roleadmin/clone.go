package roleadmin

func cloneRole(role Role) Role {
	role.DirectPermissions = cloneStrings(role.DirectPermissions)
	role.ParentRoleIDs = cloneStrings(role.ParentRoleIDs)
	role.ExcludedPermissions = cloneStrings(role.ExcludedPermissions)
	return role
}

func cloneRoleMap(roles map[string]Role) map[string]Role {
	cloned := make(map[string]Role, len(roles))
	for id, role := range roles {
		cloned[id] = cloneRole(role)
	}
	return cloned
}

func cloneDeltas(deltas []PermissionDelta) []PermissionDelta {
	cloned := make([]PermissionDelta, len(deltas))
	for i, delta := range deltas {
		delta.InheritedFrom = cloneStrings(delta.InheritedFrom)
		cloned[i] = delta
	}
	return cloned
}

func cloneRoleRefs(refs []RoleRef) []RoleRef {
	cloned := make([]RoleRef, len(refs))
	copy(cloned, refs)
	return cloned
}

func cloneApprovalItems(items []ApprovalItem) []ApprovalItem {
	cloned := make([]ApprovalItem, len(items))
	for i, item := range items {
		item.InheritedFrom = cloneStrings(item.InheritedFrom)
		cloned[i] = item
	}
	return cloned
}

func cloneDiff(diff RoleDiff) RoleDiff {
	diff.Added = cloneDeltas(diff.Added)
	diff.Removed = cloneDeltas(diff.Removed)
	diff.Inherited.ParentsAdded = cloneRoleRefs(diff.Inherited.ParentsAdded)
	diff.Inherited.ParentsRemoved = cloneRoleRefs(diff.Inherited.ParentsRemoved)
	diff.Inherited.Added = cloneDeltas(diff.Inherited.Added)
	diff.Inherited.Removed = cloneDeltas(diff.Inherited.Removed)
	diff.ApprovalItems = cloneApprovalItems(diff.ApprovalItems)
	return diff
}

func cloneApprovalState(approval ApprovalState) ApprovalState {
	approval.Items = cloneApprovalItems(approval.Items)
	approval.ApprovedItemIDs = cloneStrings(approval.ApprovedItemIDs)
	approval.ApprovedActions = cloneStrings(approval.ApprovedActions)
	approval.RejectedActions = cloneStrings(approval.RejectedActions)
	if approval.DecidedAt != nil {
		decidedAt := *approval.DecidedAt
		approval.DecidedAt = &decidedAt
	}
	return approval
}

func cloneChangeRequest(request ChangeRequest) ChangeRequest {
	request.Diff = cloneDiff(request.Diff)
	request.ProposedRole = cloneRole(request.ProposedRole)
	request.Approval = cloneApprovalState(request.Approval)
	if request.AppliedRole != nil {
		role := cloneRole(*request.AppliedRole)
		request.AppliedRole = &role
	}
	return request
}
