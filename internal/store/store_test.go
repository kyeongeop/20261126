package store

import (
	"errors"
	"testing"

	"teamsync/internal/model"
	"teamsync/internal/perm"
)

func TestPersistenceSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := st.CreateUser("Dana")
	folder, _ := st.CreateNode("Reports", model.KindFolder, st.RootID(), nil)
	file, _ := st.CreateNode("q1.md", model.KindFile, folder.ID, nil)
	if _, err := st.SetACE(folder.ID, user.ID, model.LevelWrite); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Move(file.ID, st.RootID()); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.RootID() != st.RootID() {
		t.Fatal("root ID must stay stable across restarts")
	}
	got, ok := reopened.Node(file.ID)
	if !ok || got.Path != "/q1.md" {
		t.Fatalf("reopened file = %+v", got)
	}
	ok, _ = perm.Can(reopened, file.ID, user.ID, model.LevelRead)
	if ok {
		t.Fatal("file moved to root must not inherit the folder's old write grant")
	}
	if _, ok := reopened.User(user.ID); !ok {
		t.Fatal("users must be persisted")
	}
}

func TestRootAndValidationRules(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Move(st.RootID(), st.RootID()); !errors.Is(err, ErrMoveRoot) {
		t.Fatalf("root move err = %v", err)
	}
	if _, err := st.CreateNode("bad/name", model.KindFile, st.RootID(), nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("name err = %v", err)
	}
	if _, err := st.CreateNode("x", "symlink", st.RootID(), nil); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("kind err = %v", err)
	}
	first, _ := st.CreateNode("Dup", model.KindFolder, st.RootID(), nil)
	if _, err := st.CreateNode("Dup", model.KindFolder, st.RootID(), nil); !errors.Is(err, ErrNameConflict) {
		t.Fatal("sibling duplicate must be rejected")
	}
	other, _ := st.CreateNode("Other", model.KindFolder, st.RootID(), nil)
	if _, err := st.CreateNode("Dup", model.KindFolder, other.ID, nil); err != nil {
		t.Fatalf("same name in another folder should be allowed: %v", err)
	}
	childFile, _ := st.CreateNode("child", model.KindFile, first.ID, nil)
	if _, err := st.CreateNode("c", model.KindFile, childFile.ID, nil); !errors.Is(err, ErrParentFolder) {
		t.Fatalf("file parent err = %v", err)
	}
}
