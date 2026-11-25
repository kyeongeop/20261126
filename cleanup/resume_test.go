package cleanup

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestResumeRunContinuesFailedItemsAfterServiceRestart(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("id"))
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}

	service.SetApplyHook(func(_ *CleanupRun, item *ManifestItem) error {
		if item.PermissionID == "p-deleted" && item.Attempts == 1 {
			return errors.New("injected first-round failure")
		}
		return nil
	})
	first, err := service.ExecutePreview(preview.ID)
	if err != nil {
		t.Fatalf("ExecutePreview: %v", err)
	}
	if first.Status != RunPartial {
		t.Fatalf("first run status = %s, want partial: %+v", first.Status, first)
	}
	assertRunStatuses(t, first, map[string]ItemStatus{
		"p-valid":    ItemUnchanged,
		"p-deleted":  ItemFailed,
		"p-moved":    ItemApplied,
		"p-disabled": ItemApplied,
	})
	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if permissionByID(snapshot, "p-deleted").ID == "" {
		t.Fatal("failed permission was deleted before the retry")
	}

	reloaded := env.service(t, sequentialIDs("reloaded-id"))
	resumed, err := reloaded.ResumeRun(first.ID, nil)
	if err != nil {
		t.Fatalf("ResumeRun: %v", err)
	}
	if resumed.Status != RunCompleted {
		t.Fatalf("resumed status = %s, want completed: %+v", resumed.Status, resumed)
	}
	if resumed.Round != 2 {
		t.Fatalf("resumed round = %d, want 2", resumed.Round)
	}
	var failedAttempts int
	for _, item := range resumed.Items {
		if item.PermissionID == "p-deleted" {
			failedAttempts = item.Attempts
			if item.Status != ItemApplied {
				t.Fatalf("retried item status = %s, want applied", item.Status)
			}
			if item.LastError != "" {
				t.Fatalf("retried item still has error: %s", item.LastError)
			}
		}
	}
	if failedAttempts != 2 {
		t.Fatalf("failed item attempts = %d, want 2", failedAttempts)
	}

	snapshot, err = reloaded.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot after resume: %v", err)
	}
	if len(snapshot.Permissions) != 2 {
		t.Fatalf("permissions after resume = %+v, want two", snapshot.Permissions)
	}
	if permissionByID(snapshot, "p-deleted").ID != "" {
		t.Fatal("failed permission still exists after resume")
	}

	var manifest CleanupRun
	data, err := os.ReadFile(resumed.ManifestPath)
	if err != nil {
		t.Fatalf("read resumed manifest: %v", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode resumed manifest: %v", err)
	}
	if manifest.Status != RunCompleted || manifest.Round != 2 {
		t.Fatalf("persisted manifest = status %s round %d", manifest.Status, manifest.Round)
	}
	for _, item := range manifest.Items {
		if item.PermissionID == "p-deleted" && item.Attempts != 2 {
			t.Fatalf("persisted attempts = %d, want 2", item.Attempts)
		}
	}
}

func TestResumeRunCanRetryOnlySelectedFailedItems(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("id"))
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}
	service.SetApplyHook(func(_ *CleanupRun, item *ManifestItem) error {
		if item.PermissionID == "p-deleted" || item.PermissionID == "p-disabled" {
			return errors.New("injected failure")
		}
		return nil
	})
	first, err := service.ExecutePreview(preview.ID)
	if err != nil {
		t.Fatalf("ExecutePreview: %v", err)
	}
	if first.Status != RunPartial {
		t.Fatalf("first status = %s, want partial", first.Status)
	}

	service.SetApplyHook(nil)
	second, err := service.ResumeRun(first.ID, []string{"perm:p-deleted"})
	if err != nil {
		t.Fatalf("selected ResumeRun: %v", err)
	}
	if second.Status != RunPartial {
		t.Fatalf("selected retry status = %s, want partial", second.Status)
	}
	assertRunStatuses(t, second, map[string]ItemStatus{
		"p-deleted":  ItemApplied,
		"p-disabled": ItemFailed,
	})

	third, err := service.ResumeRun(first.ID, nil)
	if err != nil {
		t.Fatalf("final ResumeRun: %v", err)
	}
	if third.Status != RunCompleted || third.Round != 3 {
		t.Fatalf("final run = status %s round %d, want completed round 3", third.Status, third.Round)
	}
	if _, err := service.ResumeRun(first.ID, []string{"missing-item"}); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("invalid filter error = %v", err)
	}
}
