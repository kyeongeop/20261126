package roleadmin

import (
	"sort"
	"strings"
)

type permissionState struct {
	direct        bool
	inheritedFrom []string
}

func effectivePermissions(roleID string, roles map[string]Role) (map[string]permissionState, error) {
	if _, ok := roles[roleID]; !ok {
		return nil, notFound("role %s does not exist", roleID)
	}
	return resolvePermissions(roleID, roles, nil)
}

func resolvePermissions(
	roleID string,
	roles map[string]Role,
	stack []string,
) (map[string]permissionState, error) {
	role := roles[roleID]
	for _, ancestorID := range stack {
		if ancestorID == roleID {
			cycle := append(cloneStrings(stack), roleID)
			return nil, invalid(
				"inheritance_cycle",
				"role inheritance contains a cycle: %s",
				strings.Join(cycle, " -> "),
			)
		}
	}

	nextStack := append(cloneStrings(stack), roleID)
	states := make(map[string]permissionState)
	for _, parentID := range role.ParentRoleIDs {
		if _, ok := roles[parentID]; !ok {
			return nil, invalid(
				"unknown_parent_role",
				"role %s references unknown parent role %s",
				role.ID,
				parentID,
			)
		}
		parentStates, err := resolvePermissions(parentID, roles, nextStack)
		if err != nil {
			return nil, err
		}
		for action, parentState := range parentStates {
			path := append([]string{parentID}, parentState.inheritedFrom...)
			state := states[action]
			state.inheritedFrom = preferredPath(state.inheritedFrom, path)
			states[action] = state
		}
	}

	for _, action := range role.DirectPermissions {
		state := states[action]
		state.direct = true
		states[action] = state
	}
	for _, action := range role.ExcludedPermissions {
		delete(states, action)
	}
	return states, nil
}

func preferredPath(current, candidate []string) []string {
	if len(current) == 0 {
		return cloneStrings(candidate)
	}
	if len(candidate) == 0 {
		return current
	}
	if len(candidate) < len(current) {
		return cloneStrings(candidate)
	}
	if len(candidate) > len(current) {
		return current
	}
	if strings.Join(candidate, "\x00") < strings.Join(current, "\x00") {
		return cloneStrings(candidate)
	}
	return current
}

func sortedActions(states map[string]permissionState) []string {
	actions := make([]string, 0, len(states))
	for action := range states {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions
}
