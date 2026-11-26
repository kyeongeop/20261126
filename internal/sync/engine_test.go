package sync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mirrorsync/internal/manifest"
	"mirrorsync/internal/source"
)

// memorySource is an in-memory Source with injected failures for resume tests.
type memorySource struct {
	files      map[string][]byte
	failBefore int // number of reads to fail with a transient error
	failCount  int
}

func (m *memorySource) Open(_ context.Context, path string, offset int64) (source.ReadCloserAt, int64, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, 0, fmt.Errorf("%w: %s", source.ErrNotFound, path)
	}
	if offset > int64(len(data)) {
		return nil, 0, errors.New("offset beyond file")
	}
	return &memoryReader{src: m, data: data[offset:], parent: m}, int64(len(data)), nil
}

type memoryReader struct {
	src    *memorySource
	data   []byte
	pos    int
	parent *memorySource
}

func (r *memoryReader) Read(p []byte) (int, error) {
	if r.src.failCount < r.src.failBefore {
		r.src.failCount++
		return 0, errors.New("simulated network reset")
	}
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *memoryReader) Close() error { return nil }

func (r *memoryReader) HonoredOffset() bool { return true }

func digestOf(b []byte) string {
	h := sha256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func testManifest(t *testing.T, files map[string][]byte) *manifest.Manifest {
	t.Helper()
	var entries []manifest.Entry
	for path, data := range files {
		entries = append(entries, manifest.Entry{
			Path: path, Size: int64(len(data)), SHA256: digestOf(data),
		})
	}
	m := &manifest.Manifest{
		Version: manifest.ManifestVersion, ImageID: "img-test", Packages: entries,
	}
	m.RootHash = manifest.RootHash(m.Packages)
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSyncHappyPathAndSummary(t *testing.T) {
	files := map[string][]byte{
		"a.deb":     []byte("package-a-content"),
		"sub/b.rpm": []byte("package-b"),
	}
	m := testManifest(t, files)
	dest := t.TempDir()
	eng := &Engine{Src: &memorySource{files: files}, DestDir: dest}
	result, err := eng.Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.Verified != 2 || result.Report.Problems() {
		t.Fatalf("unexpected report: %+v", result.Report)
	}
	for path, data := range files {
		got, readErr := os.ReadFile(filepath.Join(dest, filepath.FromSlash(path)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("content mismatch for %s", path)
		}
	}
	if _, err := WriteSummary(dest, m, result.Report); err != nil {
		t.Fatal(err)
	}
	mismatches, checked, err := VerifyChecksums(dest, filepath.Join(dest, ChecksumsFile))
	if err != nil {
		t.Fatal(err)
	}
	if checked != 2 || len(mismatches) != 0 {
		t.Fatalf("checksums review failed: checked=%d mismatches=%+v", checked, mismatches)
	}
	summary, err := ReadSummary(filepath.Join(dest, SummaryFile))
	if err != nil {
		t.Fatal(err)
	}
	if summary.ManifestRoot != m.RootHash {
		t.Fatal("summary root hash mismatch")
	}
}

func TestSyncResumeAfterFailure(t *testing.T) {
	data := []byte(strings.Repeat("resume-data-", 500))
	files := map[string][]byte{"big.deb": data}
	m := testManifest(t, files)
	dest := t.TempDir()
	src := &memorySource{files: files, failBefore: 3}
	eng := &Engine{Src: src, DestDir: dest, MaxRetries: 5}
	result, err := eng.Run(context.Background(), m)
	if err != nil {
		t.Fatalf("sync with transient failures failed: %v", err)
	}
	if result.Report.Verified != 1 {
		t.Fatalf("package not verified: %+v", result.Report)
	}
	if result.Report.RetriedCount != 1 {
		t.Fatalf("expected one retried package, got %d", result.Report.RetriedCount)
	}
	// The state file must record completion.
	cp, err := loadCheckpoint(dest, m.ImageID)
	if err != nil {
		t.Fatal(err)
	}
	if !cp.Packages["big.deb"].Done || cp.Packages["big.deb"].BytesDone != int64(len(data)) {
		t.Fatalf("checkpoint not completed: %+v", cp.Packages["big.deb"])
	}
}

func TestSyncResumesFromExistingCheckpoint(t *testing.T) {
	data := []byte("0123456789")
	files := map[string][]byte{"p.deb": data}
	m := testManifest(t, files)
	dest := t.TempDir()

	// Simulate a previous interrupted run: partial file plus checkpoint.
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	partial := data[:6]
	if err := os.WriteFile(filepath.Join(dest, "p.deb"), partial, 0o644); err != nil {
		t.Fatal(err)
	}
	cp := newCheckpoint(m.ImageID)
	cp.Packages["p.deb"] = PackageProgress{Path: "p.deb", BytesDone: 6, TotalBytes: 10}
	if err := cp.save(dest); err != nil {
		t.Fatal(err)
	}

	eng := &Engine{Src: &memorySource{files: files}, DestDir: dest}
	result, err := eng.Run(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.ResumedCount != 1 {
		t.Fatalf("expected one resumed transfer, got %d", result.Report.ResumedCount)
	}
	got, err := os.ReadFile(filepath.Join(dest, "p.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("resumed file wrong: %q", got)
	}
}
