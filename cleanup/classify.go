package cleanup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Classifier checks permission targets on disk. An empty root treats resource
// paths as paths relative to the current working directory.
type Classifier struct {
	FilesRoot string
}

// ClassifyAll indexes users and resources once for large permission tables.
func (c Classifier) ClassifyAll(db *Database) []PreviewItem {
	users := make(map[string]User, len(db.Users))
	for _, user := range db.Users {
		users[user.ID] = user
	}
	resources := make(map[string]Resource, len(db.Resources))
	for _, resource := range db.Resources {
		resources[resource.ID] = resource
	}
	items := make([]PreviewItem, 0, len(db.Permissions))
	for _, permission := range db.Permissions {
		items = append(items, c.classifyPermission(permission, users, resources))
	}
	return items
}

func (c Classifier) Classify(db *Database, permission Permission) PreviewItem {
	users := make(map[string]User, len(db.Users))
	for _, user := range db.Users {
		users[user.ID] = user
	}
	resources := make(map[string]Resource, len(db.Resources))
	for _, resource := range db.Resources {
		resources[resource.ID] = resource
	}
	return c.classifyPermission(permission, users, resources)
}

func (c Classifier) classifyPermission(permission Permission, users map[string]User, resources map[string]Resource) PreviewItem {
	item := PreviewItem{
		ID:             "perm:" + permission.ID,
		PermissionID:   permission.ID,
		UserID:         permission.UserID,
		ResourceID:     permission.ResourceID,
		PermissionPath: cleanPath(permission.Path),
	}

	user, userFound := users[permission.UserID]
	if !userFound || !user.Active {
		item.Category = CategoryUserDisabled
		item.Action = ActionDeletePermission
		if !userFound {
			item.Reason = "granted user no longer exists"
		} else {
			item.Reason = "granted user is deactivated"
		}
		return item
	}

	resource, resourceFound := resources[permission.ResourceID]
	if !resourceFound {
		item.Category = CategoryFileDeleted
		item.Action = ActionDeletePermission
		item.Reason = "permission target no longer exists in the resource registry"
		return item
	}
	item.ResourceKind = resource.Kind
	item.CurrentPath = cleanPath(resource.Path)

	exists, err := c.targetExists(resource)
	if err != nil || !exists {
		item.Category = CategoryFileDeleted
		item.Action = ActionDeletePermission
		item.Reason = "permission target is missing from the file system"
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			item.Reason = "permission target could not be inspected: " + err.Error()
		}
		return item
	}

	if item.PermissionPath != item.CurrentPath {
		item.Category = CategoryDirectoryMoved
		item.Action = ActionUpdatePath
		if resource.Kind == ResourceDirectory {
			item.Reason = "directory moved; grant remains valid at its new path"
		} else {
			item.Reason = "containing directory moved; grant remains valid at its new path"
		}
		return item
	}

	item.Category = CategoryValid
	item.Action = ActionKeep
	item.Reason = "user is active and the permission target exists"
	return item
}

func (c Classifier) targetExists(resource Resource) (bool, error) {
	path := resource.Path
	if strings.TrimSpace(path) == "" {
		return false, os.ErrNotExist
	}
	if c.FilesRoot != "" && !filepath.IsAbs(path) {
		path = filepath.Join(c.FilesRoot, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	if resource.Kind == ResourceDirectory {
		if !info.IsDir() {
			return false, fmt.Errorf("%s is not a directory", path)
		}
		return true, nil
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s is a directory, not a file", path)
	}
	return true, nil
}

func cleanPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func summarizePreview(items []PreviewItem) PreviewSummary {
	summary := PreviewSummary{
		Total: len(items),
		ByCategory: map[Category]int{
			CategoryFileDeleted:    0,
			CategoryDirectoryMoved: 0,
			CategoryUserDisabled:   0,
			CategoryValid:          0,
		},
	}
	for _, item := range items {
		summary.ByCategory[item.Category]++
		if item.Action != ActionKeep {
			summary.Changes++
		}
	}
	return summary
}

func previewMatches(items, current []PreviewItem) bool {
	if len(items) != len(current) {
		return false
	}
	for index := range items {
		left, right := items[index], current[index]
		if left.PermissionID != right.PermissionID ||
			left.UserID != right.UserID ||
			left.PermissionPath != right.PermissionPath ||
			left.CurrentPath != right.CurrentPath ||
			left.ResourceID != right.ResourceID ||
			left.ResourceKind != right.ResourceKind ||
			left.Category != right.Category ||
			left.Action != right.Action {
			return false
		}
	}
	return true
}
