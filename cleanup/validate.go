package cleanup

import (
	"fmt"
	"strings"
)

func validateDatabase(db *Database) error {
	if db.Version != 1 {
		return fmt.Errorf("unsupported dataset version %d", db.Version)
	}
	users := make(map[string]struct{}, len(db.Users))
	for _, user := range db.Users {
		if strings.TrimSpace(user.ID) == "" {
			return fmt.Errorf("user has empty id")
		}
		if _, exists := users[user.ID]; exists {
			return fmt.Errorf("duplicate user id %q", user.ID)
		}
		users[user.ID] = struct{}{}
	}
	resources := make(map[string]struct{}, len(db.Resources))
	for _, resource := range db.Resources {
		if strings.TrimSpace(resource.ID) == "" {
			return fmt.Errorf("resource has empty id")
		}
		if _, exists := resources[resource.ID]; exists {
			return fmt.Errorf("duplicate resource id %q", resource.ID)
		}
		if resource.Kind != ResourceFile && resource.Kind != ResourceDirectory {
			return fmt.Errorf("resource %q has unsupported kind %q", resource.ID, resource.Kind)
		}
		resources[resource.ID] = struct{}{}
	}
	permissions := make(map[string]struct{}, len(db.Permissions))
	for _, permission := range db.Permissions {
		if strings.TrimSpace(permission.ID) == "" {
			return fmt.Errorf("permission has empty id")
		}
		if _, exists := permissions[permission.ID]; exists {
			return fmt.Errorf("duplicate permission id %q", permission.ID)
		}
		permissions[permission.ID] = struct{}{}
	}
	return nil
}
