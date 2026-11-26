package main

import (
	"context"
	"os"
	"testing"
)

// TestRewriteClearsSourceRules applies the replacement plan to the unsafe
// lockfile and re-checks it with a deny policy: DG101/DG103(package)/DG104
// disappear, leaving only the public name collision that requires reservation.
func TestRewriteClearsSourceRules(t *testing.T) {
	cfgPath := fixtureConfig(t, "projects", "unsafe", "depguard.json")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := CheckConfigFile(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	lockBytes, err := os.ReadFile(cfg.ResolvePath(cfg.Lockfile))
	if err != nil {
		t.Fatal(err)
	}
	fixed, changed, err := RewriteLockfile(lockBytes, report)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 4 {
		t.Fatalf("expected 4 changed entries, got %d", changed)
	}

	lf, err := ParseLockfile(fixed)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]LockEntry{}
	for _, e := range lf.Entries {
		byName[e.Name] = e
	}
	ui := byName["@acme/ui"]
	if ui.Resolved != "https://pkgs.acme.test/@acme/ui/-/ui-2.0.0.tgz" {
		t.Fatalf("ui resolved not rewritten: %s", ui.Resolved)
	}
	if ui.ViaFallback {
		t.Fatal("stale via_fallback marker should be cleared")
	}
	if ui.Integrity != "sha256:b4a09cf01295aa2c52dc9f0658e125c3be8477067ef443c7b8b85ecb533eddd1" {
		t.Fatalf("ui integrity not pinned: %s", ui.Integrity)
	}

	// Re-check the rewritten lock under a deny policy with catalog/index.
	cfg.Namespace.Fallback = "deny"
	mf, err := LoadManifestFile(cfg.ResolvePath(cfg.Manifest))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicCatalog(cfg.ResolvePath(cfg.PublicCatalog))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := LoadInternalIndex(cfg.ResolvePath(cfg.InternalIndex))
	if err != nil {
		t.Fatal(err)
	}
	recheck, err := NewChecker(cfg, mf, lf, pub, idx).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n := recheck.Summary.ByRule[RuleUndeclaredMirror]; n != 0 {
		t.Errorf("DG101 should be resolved after fix, got %d", n)
	}
	if n := recheck.Summary.ByRule[RuleLockfileOverride]; n != 0 {
		t.Errorf("DG104 should be resolved after fix, got %d", n)
	}
	if n := len(ruleFindings(recheck, RuleInternalPrefixFallback, "@acme/ui")); n != 0 {
		t.Errorf("package DG103 should be resolved after fix, got %d", n)
	}
	if n := recheck.Summary.ByRule[RulePublicSameName]; n != 2 {
		t.Errorf("DG102 collisions require public reservation and should remain (2), got %d", n)
	}
}
