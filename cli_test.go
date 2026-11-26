package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const unsafeConfig = "fixtures/projects/unsafe/depguard.json"
const safeConfig = "fixtures/projects/safe/depguard.json"

func TestCheckCLIUnsafeText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"check", "-config", unsafeConfig}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"DG101", "DG102", "DG103", "DG104",
		"未声明镜像", "同名公共包", "内部前缀回退", "锁文件覆盖",
		"被替换来源", "候选来源", "pkgs.acme.test",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
}

func TestCheckCLISafePasses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"check", "-config", safeConfig}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d output=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Error("safe run should report PASS")
	}
}

func TestCheckCLIJSONContract(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"check", "-config", unsafeConfig, "-json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	var rep Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("json report: %v\n%s", err, stdout.String())
	}
	if rep.OK {
		t.Error("report must be failing")
	}
	if rep.Schema != "depguard.report/v1" {
		t.Errorf("unexpected schema %q", rep.Schema)
	}
	if rep.Summary.ByRule[RuleUndeclaredMirror] != 2 {
		t.Errorf("DG101 count = %d want 2", rep.Summary.ByRule[RuleUndeclaredMirror])
	}
	if len(rep.Replacements) != 4 {
		t.Errorf("replacements = %d want 4", len(rep.Replacements))
	}
}

func TestFixCLI(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "fixed.json")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"fix", "-config", unsafeConfig, "-out", outFile}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("fix exit = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "rewrote 4") {
		t.Fatalf("expected rewrite count message, got %q", stderr.String())
	}
}

func TestPackCLI(t *testing.T) {
	outTar := filepath.Join(t.TempDir(), "core.tar")
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"pack", "-src", "fixtures/pkgroot/acme-core",
		"-name", "@acme/core", "-version", "1.4.0", "-out", outTar,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("pack exit = %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "sha256:8a679649f6fc387cfe8dd79a77c906f67e484cbf36a640f51b49753e22622d5a") {
		t.Fatalf("pack output missing expected digest: %s", stdout.String())
	}
}

func TestUsageExit2(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check"}, &stdout, &stderr); code != 2 {
		t.Fatalf("missing -config should exit 2, got %d", code)
	}
	if code := Run([]string{"nope"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown command should exit 2, got %d", code)
	}
}

func TestSeedCLIIdempotent(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"seed", "-config", unsafeConfig, "-data", data}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("seed exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "seeded @acme/core@1.4.0") {
		t.Fatalf("seed output missing core: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "sha256:8a679649") {
		t.Fatalf("seed output missing digest: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"seed", "-config", unsafeConfig, "-data", data}, &stdout, &stderr); code != 0 {
		t.Fatalf("second seed exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "0 published, 3 already present") {
		t.Fatalf("expected idempotent rerun message, got %q", stderr.String())
	}
}
