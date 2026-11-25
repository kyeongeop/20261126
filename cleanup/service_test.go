package cleanup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type testEnvironment struct {
	root      string
	storePath string
	dataPath  string
	manifest  string
	db        *Database
}

func newTestEnvironment(t *testing.T) testEnvironment {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "files")
	mustMkdirAll(t, filepath.Join(root, "live"))
	mustMkdirAll(t, filepath.Join(root, "moved", "new-team"))
	mustWriteFile(t, filepath.Join(root, "live", "active.txt"), "active")
	mustWriteFile(t, filepath.Join(root, "live", "inactive.txt"), "inactive")

	db := &Database{
		Version:  1,
		Revision: 7,
		Users: []User{
			{ID: "u-active", Name: "Active", Active: true},
			{ID: "u-disabled", Name: "Disabled", Active: false},
		},
		Resources: []Resource{
			{ID: "r-valid", Path: "live/active.txt", Kind: ResourceFile},
			{ID: "r-deleted", Path: "gone/deleted.txt", Kind: ResourceFile},
			{ID: "r-moved", Path: "moved/new-team", Kind: ResourceDirectory},
			{ID: "r-inactive", Path: "live/inactive.txt", Kind: ResourceFile},
		},
		Permissions: []Permission{
			{ID: "p-valid", UserID: "u-active", ResourceID: "r-valid", Path: "live/active.txt"},
			{ID: "p-deleted", UserID: "u-active", ResourceID: "r-deleted", Path: "gone/deleted.txt"},
			{ID: "p-moved", UserID: "u-active", ResourceID: "r-moved", Path: "moved/old-team"},
			{ID: "p-disabled", UserID: "u-disabled", ResourceID: "r-inactive", Path: "live/inactive.txt"},
		},
	}
	env := testEnvironment{
		root:      root,
		storePath: filepath.Join(base, "data", "store.json"),
		dataPath:  filepath.Join(base, "data"),
		manifest:  filepath.Join(base, "manifests"),
		db:        db,
	}
	writeDataset(t, env.storePath, db)
	return env
}

func (e testEnvironment) service(t *testing.T, newID func() string) *Service {
	t.Helper()
	service, err := NewService(Config{
		StorePath:   e.storePath,
		ManifestDir: e.manifest,
		FilesRoot:   e.root,
		Now:         fixedClock(),
		NewID:       newID,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func fixedClock() func() time.Time {
	current := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	return func() time.Time {
		current = current.Add(time.Second)
		return current
	}
}

func sequentialIDs(prefix string) func() string {
	var sequence atomic.Int64
	return func() string {
		return fmt.Sprintf("%s-%d", prefix, sequence.Add(1))
	}
}

func writeDataset(t *testing.T, path string, db *Database) {
	t.Helper()
	normalizeDatabase(db)
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		t.Fatalf("marshal dataset: %v", err)
	}
	mustMkdirAll(t, filepath.Dir(path))
	mustWriteFile(t, path, string(data))
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func TestCreatePreviewClassifiesFourCategoriesWithoutMutating(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("id"))

	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}
	if preview.StateRevision != 7 {
		t.Fatalf("state revision = %d, want 7", preview.StateRevision)
	}
	if preview.Summary.Total != 4 || preview.Summary.Changes != 3 {
		t.Fatalf("summary = %+v, want total=4 changes=3", preview.Summary)
	}
	wantCounts := map[Category]int{
		CategoryFileDeleted:    1,
		CategoryDirectoryMoved: 1,
		CategoryUserDisabled:   1,
		CategoryValid:          1,
	}
	for category, want := range wantCounts {
		if got := preview.Summary.ByCategory[category]; got != want {
			t.Errorf("count[%s] = %d, want %d", category, got, want)
		}
	}

	items := previewByPermission(preview)
	assertPreview(t, items["p-valid"], CategoryValid, ActionKeep)
	assertPreview(t, items["p-deleted"], CategoryFileDeleted, ActionDeletePermission)
	assertPreview(t, items["p-moved"], CategoryDirectoryMoved, ActionUpdatePath)
	assertPreview(t, items["p-disabled"], CategoryUserDisabled, ActionDeletePermission)

	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Revision != 7 || len(snapshot.Permissions) != 4 {
		t.Fatalf("preview mutated permissions: revision=%d permissions=%d", snapshot.Revision, len(snapshot.Permissions))
	}
	if got := snapshot.Permissions[2].Path; got != "moved/old-team" {
		t.Fatalf("preview changed permission path to %q", got)
	}
}

func TestEmptyDatasetProducesEmptyCompletedRun(t *testing.T) {
	base := t.TempDir()
	service, err := NewService(Config{
		StorePath:   filepath.Join(base, "store.json"),
		ManifestDir: filepath.Join(base, "manifests"),
		FilesRoot:   base,
		Now:         fixedClock(),
		NewID:       sequentialIDs("empty"),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}
	if preview.Summary.Total != 0 || preview.Summary.Changes != 0 {
		t.Fatalf("empty preview summary = %+v", preview.Summary)
	}
	for _, category := range []Category{
		CategoryFileDeleted,
		CategoryDirectoryMoved,
		CategoryUserDisabled,
		CategoryValid,
	} {
		if _, ok := preview.Summary.ByCategory[category]; !ok {
			t.Errorf("empty summary missing category %s", category)
		}
	}
	run, err := service.ExecutePreview(preview.ID)
	if err != nil {
		t.Fatalf("ExecutePreview: %v", err)
	}
	if run.Status != RunCompleted || len(run.Items) != 0 {
		t.Fatalf("empty run = %+v", run)
	}
}

func TestExecutePreviewAppliesChangesAndWritesManifest(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("id"))
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}

	run, err := service.ExecutePreview(preview.ID)
	if err != nil {
		t.Fatalf("ExecutePreview: %v", err)
	}
	if run.Status != RunCompleted {
		t.Fatalf("run status = %s, want completed: %+v", run.Status, run)
	}
	if run.Round != 1 {
		t.Fatalf("round = %d, want 1", run.Round)
	}
	if run.ManifestPath == "" {
		t.Fatal("run has no manifest path")
	}
	assertRunStatuses(t, run, map[string]ItemStatus{
		"p-valid":    ItemUnchanged,
		"p-deleted":  ItemApplied,
		"p-moved":    ItemApplied,
		"p-disabled": ItemApplied,
	})

	snapshot, err := service.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Revision != 10 {
		t.Fatalf("revision = %d, want 10", snapshot.Revision)
	}
	if len(snapshot.Permissions) != 2 {
		t.Fatalf("permissions = %+v, want two remaining", snapshot.Permissions)
	}
	if got := permissionByID(snapshot, "p-moved").Path; got != "moved/new-team" {
		t.Fatalf("moved permission path = %q", got)
	}
	if permissionByID(snapshot, "p-valid").ID == "" {
		t.Fatal("valid permission was removed")
	}

	var manifest CleanupRun
	data, err := os.ReadFile(run.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.ID != run.ID || manifest.Status != RunCompleted || len(manifest.Items) != 4 {
		t.Fatalf("manifest mismatch: %+v", manifest)
	}
	for _, item := range manifest.Items {
		if item.PermissionID == "p-moved" {
			if item.Change == nil || item.Change.After == nil || item.Change.After.Path != "moved/new-team" {
				t.Fatalf("manifest moved change = %+v", item.Change)
			}
		}
	}
}

func TestExecutePreviewRejectsStalePreview(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("id"))
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}
	if _, err := service.ExecutePreview(preview.ID); err != nil {
		t.Fatalf("first ExecutePreview: %v", err)
	}
	if _, err := service.ExecutePreview(preview.ID); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("second ExecutePreview error = %v, want ErrStalePreview", err)
	}
}

func TestExecutePreviewRejectsFileSystemChangesAfterPreview(t *testing.T) {
	env := newTestEnvironment(t)
	service := env.service(t, sequentialIDs("id"))
	preview, err := service.CreatePreview()
	if err != nil {
		t.Fatalf("CreatePreview: %v", err)
	}
	if err := os.Remove(filepath.Join(env.root, "live", "active.txt")); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if _, err := service.ExecutePreview(preview.ID); !errors.Is(err, ErrStalePreview) {
		t.Fatalf("ExecutePreview error = %v, want ErrStalePreview", err)
	}
}

func previewByPermission(preview Preview) map[string]PreviewItem {
	items := make(map[string]PreviewItem, len(preview.Items))
	for _, item := range preview.Items {
		items[item.PermissionID] = item
	}
	return items
}

func assertPreview(t *testing.T, item PreviewItem, category Category, action Action) {
	t.Helper()
	if item.Category != category || item.Action != action {
		t.Errorf("permission %s = (%s, %s), want (%s, %s)", item.PermissionID, item.Category, item.Action, category, action)
	}
}

func assertRunStatuses(t *testing.T, run CleanupRun, statuses map[string]ItemStatus) {
	t.Helper()
	for _, item := range run.Items {
		if want, ok := statuses[item.PermissionID]; ok && item.Status != want {
			t.Errorf("item %s status = %s, want %s", item.PermissionID, item.Status, want)
		}
	}
}

func permissionByID(db *Database, id string) Permission {
	for _, permission := range db.Permissions {
		if permission.ID == id {
			return permission
		}
	}
	return Permission{}
}
