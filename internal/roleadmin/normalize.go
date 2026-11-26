package roleadmin

import (
	"sort"
	"strings"
	"unicode/utf8"
)

func normalizeRoleUpdate(base Role, input RoleUpdate) (Role, error) {
	if input.BaseVersion != 0 && input.BaseVersion != base.Version {
		return Role{}, conflict(
			"version_conflict",
			"role %s is at version %d, not %d",
			base.ID,
			base.Version,
			input.BaseVersion,
		)
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = base.Name
	}
	if utf8.RuneCountInString(name) > 128 {
		return Role{}, invalid("invalid_name", "role name must be at most 128 characters")
	}

	direct, err := normalizeActions(input.DirectPermissions, "direct_permissions")
	if err != nil {
		return Role{}, err
	}
	if input.DirectPermissions == nil {
		direct = cloneStrings(base.DirectPermissions)
	}

	parents, err := normalizeIdentifiers(input.ParentRoleIDs, "parent_role_ids")
	if err != nil {
		return Role{}, err
	}
	if input.ParentRoleIDs == nil {
		parents = cloneStrings(base.ParentRoleIDs)
	}
	for _, parentID := range parents {
		if parentID == base.ID {
			return Role{}, invalid("invalid_inheritance", "role %s cannot inherit from itself", base.ID)
		}
	}

	excluded, err := normalizeActions(input.ExcludedPermissions, "excluded_permissions")
	if err != nil {
		return Role{}, err
	}
	if input.ExcludedPermissions == nil {
		excluded = cloneStrings(base.ExcludedPermissions)
	}

	return Role{
		ID:                  base.ID,
		Name:                name,
		Version:             base.Version + 1,
		DirectPermissions:   direct,
		ParentRoleIDs:       parents,
		ExcludedPermissions: excluded,
	}, nil
}

func normalizeActions(values []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	actions := make([]string, 0, len(values))
	for _, raw := range values {
		action := strings.TrimSpace(raw)
		if action == "" {
			return nil, invalid("invalid_action", "%s contains an empty action", field)
		}
		if strings.IndexFunc(action, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\r' || r == '\n'
		}) >= 0 {
			return nil, invalid("invalid_action", "action %q must not contain whitespace", action)
		}
		if utf8.RuneCountInString(action) > 255 {
			return nil, invalid("invalid_action", "action %q is too long", action)
		}
		if _, ok := seen[action]; ok {
			continue
		}
		seen[action] = struct{}{}
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions, nil
}

func normalizeIdentifiers(values []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	ids := make([]string, 0, len(values))
	for _, raw := range values {
		id := strings.TrimSpace(raw)
		if id == "" {
			return nil, invalid("invalid_identifier", "%s contains an empty identifier", field)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func cloneStrings(values []string) []string {
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
