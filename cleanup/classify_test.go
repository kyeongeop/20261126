package cleanup

import (
	"path/filepath"
	"testing"
)

func TestClassifierHandlesFileInsideMovedDirectory(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "teams", "new"))
	mustWriteFile(t, filepath.Join(root, "teams", "new", "roadmap.md"), "# roadmap")
	db := &Database{
		Version: 1,
		Users: []User{
			{ID: "u1", Active: true},
		},
		Resources: []Resource{
			{ID: "r1", Path: "teams/new/roadmap.md", Kind: ResourceFile},
		},
		Permissions: []Permission{
			{ID: "p1", UserID: "u1", ResourceID: "r1", Path: "teams/old/roadmap.md"},
		},
	}
	item := (Classifier{FilesRoot: root}).Classify(db, db.Permissions[0])
	if item.Category != CategoryDirectoryMoved || item.Action != ActionUpdatePath {
		t.Fatalf("classification = (%s, %s), want (%s, %s)",
			item.Category, item.Action, CategoryDirectoryMoved, ActionUpdatePath)
	}
	if item.CurrentPath != "teams/new/roadmap.md" {
		t.Fatalf("current path = %q", item.CurrentPath)
	}
}

func TestClassifierPrefersDisabledUserOverMissingTarget(t *testing.T) {
	db := &Database{
		Version: 1,
		Users: []User{
			{ID: "u1", Active: false},
		},
		Resources: []Resource{
			{ID: "r1", Path: "missing.txt", Kind: ResourceFile},
		},
		Permissions: []Permission{
			{ID: "p1", UserID: "u1", ResourceID: "r1", Path: "missing.txt"},
		},
	}
	item := (Classifier{FilesRoot: t.TempDir()}).Classify(db, db.Permissions[0])
	if item.Category != CategoryUserDisabled || item.Action != ActionDeletePermission {
		t.Fatalf("classification = (%s, %s), want user_disabled/delete", item.Category, item.Action)
	}
}

func TestClassifierTreatsMissingUserAsDisabled(t *testing.T) {
	db := &Database{
		Version: 1,
		Permissions: []Permission{
			{ID: "p1", UserID: "deleted-user", ResourceID: "r1", Path: "missing.txt"},
		},
	}
	item := (Classifier{}).Classify(db, db.Permissions[0])
	if item.Category != CategoryUserDisabled {
		t.Fatalf("category = %s, want user_disabled", item.Category)
	}
}
