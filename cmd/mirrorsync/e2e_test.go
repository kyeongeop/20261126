package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEndToEnd builds the CLI and exercises the complete offline workflow in
// a temporary workspace, including signature verification and review on a
// second "machine" (a separate directory containing only the artifacts).
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test runs the compiled binary")
	}
	binary := filepath.Join(t.TempDir(), "mirrorsync")
	build := exec.Command("go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	ws := t.TempDir()
	pubDir := filepath.Join(ws, "publisher")
	if err := os.MkdirAll(filepath.Join(pubDir, "pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeE2EFile(t, filepath.Join(pubDir, "pool", "alpha.deb"), strings.Repeat("alpha", 200))
	writeE2EFile(t, filepath.Join(pubDir, "beta.rpm"), strings.Repeat("beta", 100))

	run := func(args ...string) string {
		cmd := exec.Command(binary, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%q failed: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	p := func(name string) string { return filepath.Join(ws, name) }

	// PKI: root -> intermediate CA -> leaf signer.
	run("keygen", "--subject", "root-ca", "--key", p("root.key"))
	run("root-cert", "--key", p("root.key"), "--cert", p("root.cert"))
	run("keygen", "--subject", "intermediate", "--key", p("ca.key"))
	run("issue-cert", "--ca-key", p("root.key"), "--ca-cert", p("root.cert"),
		"--subject", "intermediate", "--key", p("ca.key"), "--cert", p("ca.cert"), "--ca", "true")
	run("keygen", "--subject", "signer", "--key", p("leaf.key"))
	run("issue-cert", "--ca-key", p("ca.key"), "--ca-cert", p("ca.cert"),
		"--subject", "signer", "--key", p("leaf.key"), "--cert", p("leaf.cert"))

	// Manifest and signature chain.
	run("build", "--image", pubDir, "--image-id", "e2e-image", "--manifest", p("manifest.json"))
	run("sign", "--key", p("leaf.key"), "--cert", p("leaf.cert"),
		"--chain", p("ca.cert")+","+p("root.cert"),
		"--manifest", p("manifest.json"), "--signature", p("signature.json"))

	// Sync over HTTP using the in-process file server logic via a second
	// binary invocation.
	srv := exec.Command(binary, "serve", "--addr", "127.0.0.1:18080", "--image", pubDir)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_ = srv.Wait()
	}()
	waitForServer(t, "127.0.0.1:18080")

	dest := filepath.Join(ws, "replica")
	syncOut := run("sync", "--source", "http://127.0.0.1:18080/",
		"--dest", dest, "--manifest", p("manifest.json"),
		"--signature", p("signature.json"), "--root-cert", p("root.cert"))
	if !strings.Contains(syncOut, "2 verified") {
		t.Fatalf("sync did not verify both packages:\n%s", syncOut)
	}

	// A second run is a no-op resume path and must still verify.
	again := run("sync", "--source", "http://127.0.0.1:18080/",
		"--dest", dest, "--manifest", p("manifest.json"),
		"--signature", p("signature.json"), "--root-cert", p("root.cert"))
	if !strings.Contains(again, "2 verified") {
		t.Fatalf("resume run failed:\n%s", again)
	}

	// Cross-machine review using only the replica and summary artifacts.
	reviewOut := run("review", "--image", dest, "--summary", filepath.Join(dest, "sync-summary.json"),
		"--manifest", p("manifest.json"),
		"--signature", p("signature.json"), "--root-cert", p("root.cert"))
	if !strings.Contains(reviewOut, "all packages match") {
		t.Fatalf("review failed:\n%s", reviewOut)
	}

	// Tamper a package and confirm the review exits non-zero and reports it.
	tampered := filepath.Join(dest, "pool", "alpha.deb")
	if err := os.WriteFile(tampered, []byte("tampered-bytes-here"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "review", "--image", dest,
		"--summary", filepath.Join(dest, "sync-summary.json"),
		"--checksums", filepath.Join(dest, "SHA256SUMS.txt"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("tampered package was not detected:\n%s", out)
	}
	if !strings.Contains(string(out), "alpha.deb") {
		t.Fatalf("review output should name the tampered package:\n%s", out)
	}
}

func writeE2EFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := timeNow().Add(5_000_000_000)
	for timeNow().Before(deadline) {
		conn, err := dialTimeout("tcp", addr, 200_000_000)
		if err == nil {
			conn.Close()
			return
		}
		sleep100()
	}
	t.Fatalf("test server on %s did not start", addr)
}
