package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootHashBindsOrderAndContent(t *testing.T) {
	entries := []Entry{
		{Path: "a.deb", Size: 10, SHA256: strings.Repeat("a", 64)},
		{Path: "b.deb", Size: 20, SHA256: strings.Repeat("b", 64)},
	}
	root := RootHash(entries)
	if root == "" || len(root) != 64 {
		t.Fatalf("unexpected root hash %q", root)
	}

	// Reordering must change the root.
	reordered := []Entry{entries[1], entries[0]}
	if RootHash(reordered) == root {
		t.Fatal("root hash did not change after reordering entries")
	}

	// Tampering with one digest must change the root.
	tampered := []Entry{entries[0], {Path: "b.deb", Size: 20, SHA256: strings.Repeat("c", 64)}}
	if RootHash(tampered) == root {
		t.Fatal("root hash did not change after tampering a digest")
	}
}

func TestParseRejectsTamperedChainAndDuplicates(t *testing.T) {
	entries := []Entry{{Path: "pkg/a.rpm", Size: 4, SHA256: strings.Repeat("0", 64)}}
	m := &Manifest{
		Version: ManifestVersion, ImageID: "img-1",
		Packages: entries, RootHash: RootHash(entries),
	}
	data, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	// Tamper with the digest without refreshing the root chain.
	tampered := strings.Replace(string(data), strings.Repeat("0", 64), strings.Repeat("1", 64), 1)
	if _, err := Parse([]byte(tampered)); err == nil {
		t.Fatal("tampered manifest was accepted")
	}

	// Duplicate package paths must be rejected at parse time.
	dup := &Manifest{
		Version: ManifestVersion, ImageID: "img-1",
		Packages: []Entry{entries[0], entries[0]},
	}
	dup.RootHash = RootHash(dup.Packages)
	dupData, _ := dup.Marshal()
	if _, err := Parse(dupData); err == nil {
		t.Fatal("manifest with duplicate paths was accepted")
	}
}

func TestValidatePathSafety(t *testing.T) {
	good := []string{"a.deb", "dir/a.rpm", "x/y/z.tar.gz"}
	for _, p := range good {
		if err := ValidatePath(p); err != nil {
			t.Errorf("path %q rejected: %v", p, err)
		}
	}
	bad := []string{"", "/etc/passwd", "../escape", "dir/../../x", "a//b", "a/./b", "a/"}
	for _, p := range bad {
		if err := ValidatePath(p); err == nil {
			t.Errorf("unsafe path %q accepted", p)
		}
	}
}

func TestBuildHashesDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "one.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "two.txt"), []byte("world!"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Build(root, "img-build")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Packages) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m.Packages))
	}
	if m.Packages[0].Path != "one.txt" {
		t.Fatalf("entries not sorted: %q", m.Packages[0].Path)
	}
	if m.Packages[0].Size != 5 {
		t.Fatalf("wrong size: %d", m.Packages[0].Size)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("built manifest invalid: %v", err)
	}
}
