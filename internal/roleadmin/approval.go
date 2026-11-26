package roleadmin

import (
	"sort"
	"strings"
)

func selectApprovalItems(
	items []ApprovalItem,
	input DecisionInput,
) (map[string]bool, error) {
	byID := make(map[string]ApprovalItem, len(items))
	byAction := make(map[string]ApprovalItem, len(items))
	for _, item := range items {
		byID[item.ID] = item
		byAction[item.Action] = item
	}
	if input.ApproveAll {
		if len(input.ApprovedActions) > 0 || len(input.ApprovedItemIDs) > 0 {
			return nil, badRequest(
				"invalid_decision",
				"approve_all cannot be combined with selected actions",
			)
		}
		selected := make(map[string]bool, len(items))
		for _, item := range items {
			selected[item.ID] = true
		}
		return selected, nil
	}

	selected := make(map[string]bool)
	for _, itemID := range input.ApprovedItemIDs {
		itemID = strings.TrimSpace(itemID)
		if _, exists := byID[itemID]; !exists {
			return nil, badRequest(
				"unknown_approval_item",
				"%s is not a sensitive action in this request",
				itemID,
			)
		}
		selected[itemID] = true
	}
	for _, value := range input.ApprovedActions {
		value = strings.TrimSpace(value)
		if item, exists := byID[value]; exists {
			selected[item.ID] = true
			continue
		}
		item, exists := byAction[value]
		if !exists {
			return nil, badRequest(
				"unknown_approval_action",
				"%s is not a sensitive action in this request",
				value,
			)
		}
		selected[item.ID] = true
	}
	if len(selected) == 0 {
		return nil, badRequest(
			"approval_selection_required",
			"select at least one sensitive action or set approve_all",
		)
	}
	return selected, nil
}

func applyApprovedSelection(
	target Role,
	items []ApprovalItem,
	selected map[string]bool,
) Role {
	final := cloneRole(target)
	direct := stringSet(final.DirectPermissions)
	excluded := stringSet(final.ExcludedPermissions)
	for _, item := range items {
		if selected[item.ID] {
			continue
		}
		switch item.Operation {
		case "added":
			delete(direct, item.Action)
			if len(item.InheritedFrom) > 0 {
				excluded[item.Action] = struct{}{}
			}
		case "removed":
			delete(excluded, item.Action)
			direct[item.Action] = struct{}{}
		}
	}
	final.DirectPermissions = sortedSet(direct)
	final.ExcludedPermissions = sortedSet(excluded)
	return final
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func sortedSet(values map[string]struct{}) []string {
	sorted := make([]string, 0, len(values))
	for value := range values {
		sorted = append(sorted, value)
	}
	sort.Strings(sorted)
	return sorted
}

func selectedActions(items []ApprovalItem, selected map[string]bool, includeSelected bool) []string {
	actions := make([]string, 0)
	for _, item := range items {
		if selected[item.ID] == includeSelected {
			actions = append(actions, item.Action)
		}
	}
	sort.Strings(actions)
	return actions
}

func allApprovalActions(items []ApprovalItem) []string {
	actions := make([]string, 0, len(items))
	for _, item := range items {
		actions = append(actions, item.Action)
	}
	sort.Strings(actions)
	return actions
}
