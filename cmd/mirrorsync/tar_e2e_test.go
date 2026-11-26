package main

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTarBundleSyncAndDuplicateDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test runs the compiled binary")
	}
	binary := filepath.Join(t.TempDir(), "mirrorsync")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	ws := t.TempDir()
	pub := filepath.Join(ws, "publisher")
	pkgContent := strings.Repeat("offline-package", 64)
	writeE2EFile(t, filepath.Join(pub, "pool", "c.deb"), pkgContent)

	run := func(args ...string) string {
		out, err := exec.Command(binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%q failed: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	p := func(n string) string { return filepath.Join(ws, n) }
	run("keygen", "--subject", "root", "--key", p("root.key"))
	run("root-cert", "--key", p("root.key"), "--cert", p("root.cert"))
	run("keygen", "--subject", "leaf", "--key", p("leaf.key"))
	run("issue-cert", "--ca-key", p("root.key"), "--ca-cert", p("root.cert"),
		"--subject", "leaf", "--key", p("leaf.key"), "--cert", p("leaf.cert"))
	run("build", "--image", pub, "--image-id", "tar-image", "--manifest", p("manifest.json"))
	run("sign", "--key", p("leaf.key"), "--cert", p("leaf.cert"),
		"--chain", p("root.cert"), "--manifest", p("manifest.json"),
		"--signature", p("signature.json"))

	// Build a tar bundle containing the package twice to prove duplicate
	// entries are detected rather than silently overwriting each other.
	bundle := p("bundle.tar")
	createBundle(t, bundle, map[string]string{"pool/c.deb": pkgContent}, true)

	dest := filepath.Join(ws, "replica")
	out, err := exec.Command(binary, "sync", "--source", bundle, "--dest", dest,
		"--manifest", p("manifest.json"), "--signature", p("signature.json"),
		"--root-cert", p("root.cert")).CombinedOutput()
	if err == nil {
		t.Fatalf("sync with duplicate bundle should exit non-zero:\n%s", out)
	}
	if !strings.Contains(string(out), "DUPLICATED") || !strings.Contains(string(out), "pool/c.deb") {
		t.Fatalf("duplicate bundle entry not reported:\n%s", out)
	}

	// A clean bundle synchronizes fully and survives a review.
	cleanBundle := p("clean.tar")
	createBundle(t, cleanBundle, map[string]string{"pool/c.deb": pkgContent}, false)
	cleanDest := filepath.Join(ws, "clean-replica")
	syncOut := run("sync", "--source", cleanBundle, "--dest", cleanDest,
		"--manifest", p("manifest.json"), "--signature", p("signature.json"),
		"--root-cert", p("root.cert"))
	if !strings.Contains(syncOut, "1 verified") {
		t.Fatalf("tar sync failed:\n%s", syncOut)
	}
	reviewOut := run("review", "--image", cleanDest,
		"--summary", filepath.Join(cleanDest, "sync-summary.json"),
		"--checksums", filepath.Join(cleanDest, "SHA256SUMS.txt"))
	if !strings.Contains(reviewOut, "all packages match") {
		t.Fatalf("tar review failed:\n%s", reviewOut)
	}
}

func createBundle(t *testing.T, path string, files map[string]string, duplicateFirst bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
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
	for name, content := range files {
		if duplicateFirst {
			add(name, "stale-copy")
		}
		add(name, content)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}
