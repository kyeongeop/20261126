package store

import (
	"errors"
	"testing"

	"teamsync/internal/model"
	"teamsync/internal/perm"
)

func mustUser(t *testing.T, st *Store, name string) *model.User {
	t.Helper()
	user, err := st.CreateUser(name)
	if err != nil {
		t.Fatalf("create user %q: %v", name, err)
	}
	return user
}

func mustNode(t *testing.T, st *Store, name, kind, parent string) *model.Node {
	t.Helper()
	node, err := st.CreateNode(name, kind, parent, nil)
	if err != nil {
		t.Fatalf("create node %q: %v", name, err)
	}
	return node
}

func mustACE(t *testing.T, st *Store, nodeID, userID, level string) {
	t.Helper()
	if _, err := st.SetACE(nodeID, userID, level); err != nil {
		t.Fatalf("set ace %s/%s=%s: %v", nodeID, userID, level, err)
	}
}

func entryFor(entries []model.EffectiveEntry, userID string) (model.EffectiveEntry, bool) {
	for _, entry := range entries {
		if entry.UserID == userID {
			return entry, true
		}
	}
	return model.EffectiveEntry{}, false
}

// buildDeepTree creates root/L1/L2/L3/L4 with leaf.md inside L4.
func buildDeepTree(t *testing.T, st *Store) []*model.Node {
	t.Helper()
	rootID := st.RootID()
	levels := []*model.Node{{ID: rootID}}
	parent := rootID
	for _, name := range []string{"L1", "L2", "L3", "L4"} {
		node := mustNode(t, st, name, model.KindFolder, parent)
		levels = append(levels, node)
		parent = node.ID
	}
	leaf := mustNode(t, st, "leaf.md", model.KindFile, parent)
	return append(levels, leaf)
}

func TestDeepDirectoryInheritance(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tree := buildDeepTree(t, st)
	rootID, leaf := tree[0].ID, tree[len(tree)-1]
	alice := mustUser(t, st, "Alice")
	mustACE(t, st, rootID, alice.ID, model.LevelRead)

	for _, node := range tree[1:] {
		ok, err := perm.Can(st, node.ID, alice.ID, model.LevelRead)
		if err != nil || !ok {
			t.Fatalf("node %s: expected inherited read, ok=%v err=%v", node.Path, ok, err)
		}
		if ok, _ := perm.Can(st, node.ID, alice.ID, model.LevelWrite); ok {
			t.Fatalf("node %s: read must not imply write", node.Path)
		}
	}

	view, err := st.Effective(leaf.ID)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := entryFor(view.Entries, alice.ID)
	if !ok {
		t.Fatal("leaf has no effective entry for Alice")
	}
	if !entry.Inherited || entry.SourceNode != rootID || entry.Depth != 0 {
		t.Fatalf("entry must point at root inheritance, got %+v", entry)
	}
	if len(view.Chain) != 6 {
		t.Fatalf("chain length = %d, want 6", len(view.Chain))
	}
}

func TestMultiLevelOverrideNearestWins(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	tree := buildDeepTree(t, st)
	rootID, l1, l2, l3, l4, leaf := tree[0].ID, tree[1].ID, tree[2].ID, tree[3].ID, tree[4].ID, tree[5].ID
	alice := mustUser(t, st, "Alice")

	mustACE(t, st, rootID, alice.ID, model.LevelRead)
	mustACE(t, st, l1, alice.ID, model.LevelWrite)
	mustACE(t, st, l3, alice.ID, model.LevelNone)

	cases := []struct {
		nodeID, want, source string
	}{
		{rootID, model.LevelRead, rootID},
		{l1, model.LevelWrite, l1},
		{l2, model.LevelWrite, l1},
		{l3, model.LevelNone, l3},
		{l4, model.LevelNone, l3},
		{leaf, model.LevelNone, l3},
	}
	for _, tc := range cases {
		entries, err := perm.Effective(st, tc.nodeID)
		if err != nil {
			t.Fatal(err)
		}
		entry, ok := entryFor(entries, alice.ID)
		if !ok {
			t.Fatalf("node %s missing entry", tc.nodeID)
		}
		if entry.Level != tc.want || entry.SourceNode != tc.source {
			t.Fatalf("node %s: got level=%s source=%s, want %s/%s",
				tc.nodeID, entry.Level, entry.SourceNode, tc.want, tc.source)
		}
	}

	if ok, _ := perm.Can(st, leaf, alice.ID, model.LevelRead); ok {
		t.Fatal("explicit none on L3 must deny the leaf")
	}
	if err := st.DeleteACE(l3, alice.ID); err != nil {
		t.Fatal(err)
	}
	entry, _, _ := perm.EffectiveForUser(st, leaf, alice.ID)
	if entry.Level != model.LevelWrite || entry.SourceNode != l1 {
		t.Fatalf("fallback = %+v, want write from L1", entry)
	}
}

func TestSameNameUsersStayIndependent(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	tree := buildDeepTree(t, st)
	rootID, l2, leaf := tree[0].ID, tree[2].ID, tree[len(tree)-1].ID

	bobA := mustUser(t, st, "Bob")
	bobB := mustUser(t, st, "Bob")
	if bobA.ID == bobB.ID {
		t.Fatal("same-name users must get distinct IDs")
	}

	mustACE(t, st, rootID, bobA.ID, model.LevelRead)
	mustACE(t, st, rootID, bobB.ID, model.LevelAdmin)
	mustACE(t, st, l2, bobA.ID, model.LevelWrite)

	entries, err := perm.Effective(st, leaf)
	if err != nil {
		t.Fatal(err)
	}
	a, okA := entryFor(entries, bobA.ID)
	b, okB := entryFor(entries, bobB.ID)
	if !okA || !okB || a.UserName != "Bob" || b.UserName != "Bob" {
		t.Fatal("both same-name users must appear with the shared name")
	}
	if a.Level != model.LevelWrite || a.SourceNode != l2 {
		t.Fatalf("Bob A = %+v, want write from L2", a)
	}
	if b.Level != model.LevelAdmin || b.SourceNode != rootID {
		t.Fatalf("Bob B = %+v, want admin from root", b)
	}

	mustACE(t, st, leaf, bobA.ID, model.LevelNone)
	if ok, _ := perm.Can(st, leaf, bobA.ID, model.LevelRead); ok {
		t.Fatal("Bob A denied by local none")
	}
	if ok, _ := perm.Can(st, leaf, bobB.ID, model.LevelAdmin); !ok {
		t.Fatal("Bob B keeps admin independently")
	}
}

func TestMoveRecomputesPermissionsAndKillsGhosts(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	rootID := st.RootID()
	eng := mustNode(t, st, "Engineering", model.KindFolder, rootID)
	sales := mustNode(t, st, "Sales", model.KindFolder, rootID)
	design := mustNode(t, st, "Design", model.KindFolder, eng.ID)
	doc := mustNode(t, st, "spec.md", model.KindFile, design.ID)

	alice := mustUser(t, st, "Alice")
	carol := mustUser(t, st, "Carol")
	mustACE(t, st, eng.ID, alice.ID, model.LevelWrite)
	mustACE(t, st, design.ID, carol.ID, model.LevelAdmin)
	mustACE(t, st, sales.ID, alice.ID, model.LevelRead)

	if ok, _ := perm.Can(st, doc.ID, alice.ID, model.LevelWrite); !ok {
		t.Fatal("pre-move Alice inherits write through Engineering")
	}

	if _, err := st.Move(design.ID, sales.ID); err != nil {
		t.Fatalf("move: %v", err)
	}
	moved, _ := st.Node(design.ID)
	if moved.ParentID != sales.ID || moved.Path != "/Sales/Design" {
		t.Fatalf("moved path = %q parent=%s", moved.Path, moved.ParentID)
	}
	movedDoc, _ := st.Node(doc.ID)
	if movedDoc.Path != "/Sales/Design/spec.md" {
		t.Fatalf("child path = %q", movedDoc.Path)
	}

	if ok, _ := perm.Can(st, doc.ID, carol.ID, model.LevelAdmin); !ok {
		t.Fatal("direct ACE must travel with the moved folder")
	}
	entry, _, err := perm.EffectiveForUser(st, doc.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Level != model.LevelRead || entry.SourceNode != sales.ID {
		t.Fatalf("ghost access survived move: %+v", entry)
	}
	if ok, _ := perm.Can(st, doc.ID, alice.ID, model.LevelWrite); ok {
		t.Fatal("stale Engineering write must not survive the move")
	}

	if _, err := st.Move(sales.ID, design.ID); !errors.Is(err, ErrMoveIntoSelf) {
		t.Fatalf("move into descendant err = %v", err)
	}
	dup := mustNode(t, st, "Design", model.KindFolder, rootID)
	if _, err := st.Move(dup.ID, sales.ID); !errors.Is(err, ErrNameConflict) {
		t.Fatalf("duplicate name err = %v", err)
	}
}
