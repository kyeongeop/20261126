package sync

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"mirrorsync/internal/source"
)

func TestMissingReplacedAndExtraClassification(t *testing.T) {
	good := []byte("correct-package")
	replaced := []byte("tampered-package")
	manifestFiles := map[string][]byte{
		"good.deb":     good,
		"missing.deb":  []byte("never-transferred"),
		"replaced.deb": []byte("original-bytes-here"),
	}
	m := testManifest(t, manifestFiles)

	// Source only carries two of the three declared packages.
	srcFiles := map[string][]byte{
		"good.deb":     good,
		"replaced.deb": replaced,
	}
	dest := t.TempDir()
	eng := &Engine{Src: &memorySource{files: srcFiles}, DestDir: dest}
	result, err := eng.Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	r := result.Report
	if r.Verified != 1 {
		t.Fatalf("expected 1 verified, got %d", r.Verified)
	}
	if len(r.Missing) != 1 || r.Missing[0].Path != "missing.deb" {
		t.Fatalf("missing classification wrong: %+v", r.Missing)
	}
	if len(r.Replaced) != 1 || r.Replaced[0].Path != "replaced.deb" {
		t.Fatalf("replaced classification wrong: %+v", r.Replaced)
	}
	if r.Replaced[0].Detail == "" || r.Replaced[0].Expected != digestOf(manifestFiles["replaced.deb"]) {
		t.Fatal("replaced finding should explain the mismatch and keep the expected digest")
	}
	// Simulate the swapped package landing on disk through another channel so
	// the offline review below classifies it as replaced rather than missing.
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "replaced.deb"), replaced, 0o644); err != nil {
		t.Fatal(err)
	}

	// Drop an undeclared file into the image: it must show up as extra.
	if err := os.WriteFile(filepath.Join(dest, "rogue.deb"), []byte("not-in-manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	review, err := VerifyImage(dest, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Extra) != 1 || review.Extra[0].Path != "rogue.deb" {
		t.Fatalf("extra classification wrong: %+v", review.Extra)
	}
	if len(review.Missing) != 1 || len(review.Replaced) != 1 {
		t.Fatalf("review must keep separate lists: %+v", review)
	}
}

func TestDuplicateSourceEntriesReported(t *testing.T) {
	data := []byte("dup-content")
	files := map[string][]byte{"dup.deb": data}
	m := testManifest(t, files)
	dest := t.TempDir()
	eng := &Engine{
		Src:     &memorySource{files: files},
		DestDir: dest,
		InspectDuplicates: func() ([]source.DuplicateEntry, error) {
			return []source.DuplicateEntry{{Path: "dup.deb", Count: 2}}, nil
		},
	}
	result, err := eng.Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Report.Duplicated) != 1 || result.Report.Duplicated[0].Status != StatusDuplicate {
		t.Fatalf("duplicate not reported: %+v", result.Report.Duplicated)
	}
}

func TestReplacedByDigestSwap(t *testing.T) {
	// Same size, different bytes: the download completes but the digest
	// check fails, so the actual digest must be recorded.
	original := []byte("aaaa-bbbb-cccc")
	swapped := []byte("dddd-eeee-ffff")
	files := map[string][]byte{"same.deb": original}
	m := testManifest(t, files)
	dest := t.TempDir()
	eng := &Engine{
		Src:     &memorySource{files: map[string][]byte{"same.deb": swapped}},
		DestDir: dest,
	}
	result, err := eng.Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Report.Replaced) != 1 {
		t.Fatalf("expected one replaced package: %+v", result.Report.Replaced)
	}
	if result.Report.Replaced[0].Actual != digestOf(swapped) {
		t.Fatalf("actual digest not recorded: %+v", result.Report.Replaced[0])
	}
}

func TestReplacedDetectedOnRerunWithoutSource(t *testing.T) {
	data := []byte("stable-content")
	files := map[string][]byte{"p.deb": data}
	m := testManifest(t, files)
	dest := t.TempDir()
	eng := &Engine{Src: &memorySource{files: files}, DestDir: dest}
	if _, err := eng.Run(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	// Tamper with the verified file after the fact.
	path := filepath.Join(dest, "p.deb")
	if err := os.WriteFile(path, []byte("changed-after-sync"), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := VerifyImage(dest, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Replaced) != 1 || report.Verified != 0 {
		t.Fatalf("tampered file not detected on review: %+v", report)
	}
}
