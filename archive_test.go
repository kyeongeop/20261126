package main

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestBuildVerifyAndDigestTar(t *testing.T) {
	files := map[string]string{
		"package/package.json": `{"name":"x"}`,
		"package/index.js":     "module.exports=1",
	}
	b1, err := BuildTar(files)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := BuildTar(files)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1, b2) {
		t.Fatal("BuildTar must be deterministic for the same inputs")
	}

	info, err := VerifyTar(bytes.NewReader(b1))
	if err != nil {
		t.Fatalf("VerifyTar: %v", err)
	}
	if info.Files != 2 {
		t.Fatalf("expected 2 files, got %d (%v)", info.Files, info.Entries)
	}

	d := DigestBytes(b1)
	norm, ok := NormalizeSHA256(d)
	if !ok || norm != d {
		t.Fatalf("digest not normalizable: %s", d)
	}
}

func TestSafeTarPathRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../evil.js", "a/../../etc/passwd", "/etc/passwd", ""} {
		if _, err := SafeTarPath(bad); err == nil {
			t.Errorf("SafeTarPath(%q) expected error", bad)
		}
	}
	if _, err := SafeTarPath("package/ok.js"); err != nil {
		t.Errorf("safe path rejected: %v", err)
	}
}

func TestVerifyTarRejectsMaliciousEntry(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: "../../../tmp/pwned", Mode: 0o644, Size: 5}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTar(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("VerifyTar must reject path-traversal entries")
	}
}
