package keyring

import (
	"path/filepath"
	"testing"
)

func TestRotationPersistsAndOldKeysRemainUsable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keyring")

	kr, err := Open(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if kr.ActiveVersion() != 1 {
		t.Fatalf("initial active version = %d, want 1", kr.ActiveVersion())
	}
	firstKey, firstMeta, err := kr.Key(1)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := kr.Rotate("bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Rotate("carol"); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk: all three KEK versions must survive a restart.
	reopened, err := Open(dir, "someone-else")
	if err != nil {
		t.Fatal(err)
	}
	if reopened.ActiveVersion() != 3 {
		t.Fatalf("active version after reopen = %d, want 3", reopened.ActiveVersion())
	}
	got, meta, err := reopened.Key(1)
	if err != nil {
		t.Fatalf("old KEK v1 unavailable after reopen: %v", err)
	}
	if string(got) != string(firstKey) {
		t.Fatal("KEK v1 material changed after rotation/reopen")
	}
	if meta.CreatedBy != "alice" || meta.SHA256 != firstMeta.SHA256 {
		t.Fatalf("KEK v1 metadata not preserved: %+v", meta)
	}

	metas := reopened.List()
	if len(metas) != 3 {
		t.Fatalf("expected 3 KEK metas, got %d", len(metas))
	}
	wantCreators := []string{"alice", "bob", "carol"}
	for i, m := range metas {
		if m.CreatedBy != wantCreators[i] {
			t.Fatalf("KEK v%d creator = %q, want %q", m.Version, m.CreatedBy, wantCreators[i])
		}
		if m.SHA256 == "" {
			t.Fatalf("KEK v%d missing checksum", m.Version)
		}
	}
}
