package source

import (
	"archive/tar"
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDirSourceOpenAndResume(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", "pkg.deb"), "0123456789")
	src, err := NewDirSource(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rc, total, err := src.Open(ctx, "a/pkg.deb", 4)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if total != 10 || string(data) != "456789" {
		t.Fatalf("resume read failed: total=%d data=%q", total, data)
	}
	if _, _, err := src.Open(ctx, "missing.deb", 0); err == nil {
		t.Fatal("missing file did not error")
	}
}

func TestHTTPSourceRangeResume(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "pkg.rpm"), "abcdefghij")
	handler, err := NewFileHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()

	src, err := NewHTTPSource(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	rc, total, err := src.Open(context.Background(), "pkg.rpm", 3)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if total != 10 || string(data) != "defghij" {
		t.Fatalf("HTTP range failed: total=%d data=%q", total, data)
	}
}

func TestTarSourceResumeAndDuplicates(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "bundle.tar")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	add := func(name, content string) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	add("dup.deb", "first")
	add("dup.deb", "second")
	add("once.deb", "hello-tar")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	src, err := NewTarSource(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	rc, total, err := src.Open(context.Background(), "once.deb", 6)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if total != 9 || string(data) != "tar" {
		t.Fatalf("tar resume failed: total=%d data=%q", total, data)
	}

	dupes, err := TarDuplicates(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(dupes) != 1 || dupes[0].Path != "dup.deb" || dupes[0].Count != 2 {
		t.Fatalf("unexpected duplicates: %+v", dupes)
	}
}
