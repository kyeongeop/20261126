package cleanup

import (
	"errors"
	"fmt"
	"time"
)

// ExecutePreview applies only the changes recorded in an existing preview.
// A preview from an older dataset revision is rejected.
func (s *Service) ExecutePreview(previewID string) (CleanupRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	preview, ok := s.db.Previews[previewID]
	if !ok {
		return CleanupRun{}, ErrNotFound
	}
	if preview.StateRevision != s.db.Revision {
		return CleanupRun{}, ErrStalePreview
	}
	if !previewMatches(preview.Items, s.classifier.ClassifyAll(s.db)) {
		return CleanupRun{}, ErrStalePreview
	}

	now := s.now()
	run := CleanupRun{
		ID:            s.uniqueRunIDLocked(),
		PreviewID:     preview.ID,
		StateRevision: preview.StateRevision,
		Status:        RunRunning,
		CreatedAt:     now,
		UpdatedAt:     now,
		Summary:       clonePreview(preview).Summary,
		Items:         make([]ManifestItem, 0, len(preview.Items)),
	}
	for _, item := range preview.Items {
		manifestItem := manifestItemFromPreview(item)
		if item.Action == ActionKeep {
			manifestItem.Status = ItemUnchanged
			manifestItem.Note = "no change required"
		}
		run.Items = append(run.Items, manifestItem)
	}
	s.db.Runs[run.ID] = run
	if err := s.persistRunLocked(&run); err != nil {
		delete(s.db.Runs, run.ID)
		return CleanupRun{}, err
	}
	if err := s.processRunLocked(&run, nil); err != nil {
		return cloneRun(run), err
	}
	return cloneRun(run), nil
}

// ResumeRun retries pending, interrupted, and failed items. Passing itemIDs
// limits the round to those manifest item IDs.
func (s *Service) ResumeRun(runID string, itemIDs []string) (CleanupRun, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	run, ok := s.db.Runs[runID]
	if !ok {
		return CleanupRun{}, ErrNotFound
	}
	filter, err := makeItemFilter(run, itemIDs)
	if err != nil {
		return CleanupRun{}, err
	}
	if run.Status == RunCompleted {
		return cloneRun(run), nil
	}
	if err := s.processRunLocked(&run, filter); err != nil {
		return cloneRun(run), err
	}
	return cloneRun(run), nil
}

func manifestItemFromPreview(item PreviewItem) ManifestItem {
	manifestItem := ManifestItem{
		ID:             item.ID,
		PermissionID:   item.PermissionID,
		UserID:         item.UserID,
		ResourceID:     item.ResourceID,
		ResourceKind:   item.ResourceKind,
		Category:       item.Category,
		Action:         item.Action,
		PermissionPath: item.PermissionPath,
		CurrentPath:    item.CurrentPath,
		Reason:         item.Reason,
		Status:         ItemPending,
	}
	if item.Action != ActionDeletePermission && item.Action != ActionUpdatePath {
		return manifestItem
	}
	before := Permission{
		ID:         item.PermissionID,
		UserID:     item.UserID,
		ResourceID: item.ResourceID,
		Path:       item.PermissionPath,
	}
	change := &PermissionChange{Action: string(item.Action), Before: &before}
	if item.Action == ActionUpdatePath {
		after := before
		after.Path = item.CurrentPath
		change.After = &after
	}
	manifestItem.Change = change
	return manifestItem
}

func (s *Service) processRunLocked(run *CleanupRun, filter map[string]struct{}) error {
	run.Status = RunRunning
	run.Round++
	run.LastError = ""
	run.CompletedAt = nil
	if err := s.persistRunLocked(run); err != nil {
		return err
	}

	for index := range run.Items {
		item := &run.Items[index]
		if filter != nil {
			if _, selected := filter[item.ID]; !selected {
				continue
			}
		}
		if !isRetryable(item.Status) {
			continue
		}

		item.Status = ItemApplying
		item.Attempts++
		item.LastError = ""
		item.Note = ""
		if err := s.persistRunLocked(run); err != nil {
			return err
		}

		if s.applyHook != nil {
			if err := s.applyHook(run, item); err != nil {
				s.markItemFailed(run, item, err)
				if err := s.persistRunLocked(run); err != nil {
					return err
				}
				continue
			}
		}
		note, err := s.applyItemLocked(run, item)
		if err != nil {
			s.markItemFailed(run, item, err)
			if err := s.persistRunLocked(run); err != nil {
				return err
			}
			continue
		}
		item.Status = ItemApplied
		item.Note = note
		item.AppliedAt = timePointer(s.now())
		if err := s.persistRunLocked(run); err != nil {
			return err
		}
	}
	finalizeRun(run, s.now())
	return s.persistRunLocked(run)
}

func isRetryable(status ItemStatus) bool {
	return status == ItemPending || status == ItemApplying || status == ItemFailed
}

func (s *Service) markItemFailed(run *CleanupRun, item *ManifestItem, err error) {
	item.Status = ItemFailed
	item.LastError = err.Error()
	if run.LastError == "" {
		run.LastError = fmt.Sprintf("%s: %v", item.ID, err)
	}
}

func (s *Service) applyItemLocked(run *CleanupRun, item *ManifestItem) (string, error) {
	index := permissionIndex(s.db, item.PermissionID)
	switch item.Action {
	case ActionDeletePermission:
		if index < 0 {
			return "permission was already absent", nil
		}
		before := s.db.Permissions[index]
		item.Change = &PermissionChange{Action: string(ActionDeletePermission), Before: &before}
		s.db.Permissions = append(s.db.Permissions[:index], s.db.Permissions[index+1:]...)
		s.db.Revision++
		return "permission deleted", nil

	case ActionUpdatePath:
		if cleanPath(item.CurrentPath) == "" {
			return "", errors.New("moved directory has no current path")
		}
		if index < 0 {
			return "permission was already removed", nil
		}
		before := s.db.Permissions[index]
		current := cleanPath(before.Path)
		target := cleanPath(item.CurrentPath)
		if current == target {
			if item.Change == nil {
				item.Change = &PermissionChange{
					Action: string(ActionUpdatePath),
					Before: &before,
				}
			}
			item.Change.After = permissionWithPath(before, target)
			return "permission path was already current", nil
		}
		if current != cleanPath(item.PermissionPath) {
			return "", fmt.Errorf("permission path changed since preview: current %q, preview %q", current, item.PermissionPath)
		}
		after := before
		after.Path = target
		item.Change = &PermissionChange{
			Action: string(ActionUpdatePath),
			Before: &before,
			After:  permissionWithPath(after, target),
		}
		s.db.Permissions[index] = after
		s.db.Revision++
		return "permission path updated", nil

	default:
		return "", fmt.Errorf("unsupported action %q", item.Action)
	}
}

func permissionIndex(db *Database, permissionID string) int {
	for index, permission := range db.Permissions {
		if permission.ID == permissionID {
			return index
		}
	}
	return -1
}

func permissionWithPath(permission Permission, path string) *Permission {
	permission.Path = path
	return &permission
}

func finalizeRun(run *CleanupRun, now time.Time) {
	var retryable, failed, applied int
	run.LastError = ""
	for _, item := range run.Items {
		if isRetryable(item.Status) {
			retryable++
		}
		if item.Status == ItemFailed {
			failed++
			if run.LastError == "" {
				run.LastError = fmt.Sprintf("%s: %s", item.ID, item.LastError)
			}
		}
		if item.Status == ItemApplied {
			applied++
		}
	}
	switch {
	case retryable == 0:
		run.Status = RunCompleted
		run.CompletedAt = timePointer(now)
	case applied > 0:
		run.Status = RunPartial
	default:
		run.Status = RunFailed
	}
	if failed > 0 && run.Status == RunPartial {
		run.LastError = fmt.Sprintf("%d item(s) failed", failed)
	}
}

func makeItemFilter(run CleanupRun, itemIDs []string) (map[string]struct{}, error) {
	if len(itemIDs) == 0 {
		return nil, nil
	}
	known := make(map[string]struct{}, len(run.Items))
	for _, item := range run.Items {
		known[item.ID] = struct{}{}
	}
	filter := make(map[string]struct{}, len(itemIDs))
	for _, id := range itemIDs {
		if _, ok := known[id]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrInvalidFilter, id)
		}
		filter[id] = struct{}{}
	}
	return filter, nil
}

func timePointer(value time.Time) *time.Time {
	return &value
}
