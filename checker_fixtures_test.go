package main

import (
	"context"
	"testing"
)

func runFixtureCheck(t *testing.T, project string) *Report {
	t.Helper()
	cfgPath := fixtureConfig(t, "projects", project, "depguard.json")
	report, err := CheckConfigFile(context.Background(), cfgPath)
	if err != nil {
		t.Fatalf("CheckConfigFile(%s): %v", cfgPath, err)
	}
	return report
}

func ruleFindings(r *Report, ruleID, pkg string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if (ruleID == "" || f.RuleID == ruleID) && (pkg == "" || f.Package == pkg) {
			out = append(out, f)
		}
	}
	return out
}

func hasRule(r *Report, ruleID, pkg string) bool {
	return len(ruleFindings(r, ruleID, pkg)) > 0
}

func TestUnsafeFixtureRuleMatrix(t *testing.T) {
	r := runFixtureCheck(t, "unsafe")

	if r.OK {
		t.Fatal("unsafe report must not be OK")
	}
	for _, id := range []string{
		RuleUndeclaredMirror,
		RulePublicSameName,
		RuleInternalPrefixFallback,
		RuleLockfileOverride,
	} {
		if r.Summary.ByRule[id] == 0 {
			t.Errorf("expected at least one %s finding", id)
		}
	}

	// @acme/core: isolated DG104 integrity override only.
	core := ruleFindings(r, "", "@acme/core")
	if len(core) != 1 || core[0].RuleID != RuleLockfileOverride {
		t.Fatalf("@acme/core expected exactly one DG104, got %+v", ruleIDs(core))
	}
	if core[0].Evidence["internal_sha256"] != "sha256:8a679649f6fc387cfe8dd79a77c906f67e484cbf36a640f51b49753e22622d5a" {
		t.Errorf("core missing trusted internal digest evidence: %+v", core[0].Evidence)
	}

	// @acme/ui: collision + prefix fallback + source override, but its public
	// host IS declared so it is not an undeclared-mirror finding.
	for _, id := range []string{RulePublicSameName, RuleInternalPrefixFallback, RuleLockfileOverride} {
		if !hasRule(r, id, "@acme/ui") {
			t.Errorf("@acme/ui missing %s", id)
		}
	}
	if hasRule(r, RuleUndeclaredMirror, "@acme/ui") {
		t.Error("@acme/ui uses the declared public registry; must not be DG101")
	}

	// acme-billing: undeclared mirror + collision + override, but it is an
	// exact (unprefixed) reservation so DG103 prefix fallback must not fire.
	for _, id := range []string{RuleUndeclaredMirror, RulePublicSameName, RuleLockfileOverride} {
		if !hasRule(r, id, "acme-billing") {
			t.Errorf("acme-billing missing %s", id)
		}
	}
	if hasRule(r, RuleInternalPrefixFallback, "acme-billing") {
		t.Error("acme-billing is an exact reservation, not a prefix; DG103 must not fire")
	}

	// random-utils is a normal external package on an unapproved host:
	// DG101 only, never a namespace collision/fallback/override.
	ru := ruleFindings(r, "", "random-utils")
	if len(ru) != 1 || ru[0].RuleID != RuleUndeclaredMirror {
		t.Fatalf("random-utils expected exactly one DG101, got %+v", ruleIDs(ru))
	}

	// Precision: legitimate public OSS and the declared mirror are clean.
	for _, name := range []string{"lodash", "express", "dayjs"} {
		if fs := ruleFindings(r, "", name); len(fs) != 0 {
			t.Errorf("%s must have no findings, got %v", name, ruleIDs(fs))
		}
	}
}

func TestUnsafeCandidatesAndReplacementPlan(t *testing.T) {
	r := runFixtureCheck(t, "unsafe")

	for _, f := range r.Findings {
		if f.Severity != SeverityError && f.Package != "" {
			continue
		}
		if f.Package == "" {
			continue // configuration-level finding has no source candidate
		}
		if f.Candidate == nil || f.Candidate.SourceURL == "" {
			t.Errorf("%s/%s missing candidate source", f.RuleID, f.Package)
		}
	}

	byPkg := map[string]SourceReplacement{}
	for _, rp := range r.Replacements {
		byPkg[rp.Package] = rp
	}

	ui, ok := byPkg["@acme/ui"]
	if !ok {
		t.Fatal("missing @acme/ui replacement")
	}
	if !ui.Candidate.Verified || ui.Candidate.SHA256 == "" {
		t.Error("ui candidate must be digest-verified from internal index")
	}
	if ui.Candidate.SourceURL != "https://pkgs.acme.test/@acme/ui/-/ui-2.0.0.tgz" {
		t.Errorf("unexpected ui candidate URL: %s", ui.Candidate.SourceURL)
	}
	if ui.ReplacedSource == "" || ui.ReplacedSource == ui.Candidate.SourceURL {
		t.Error("replaced source must be the risky public URL and differ from candidate")
	}

	ru := byPkg["random-utils"]
	if ru.Candidate.SourceURL != "https://registry.npmjs.org/random-utils/-/random-utils-1.2.0.tgz" {
		t.Errorf("bad external candidate: %s", ru.Candidate.SourceURL)
	}
}

func TestSafeFixtureHasNoFindings(t *testing.T) {
	r := runFixtureCheck(t, "safe")
	if !r.OK {
		t.Fatalf("safe report expected OK, got %d errors: %+v", r.Summary.Errors, r.Findings)
	}
	if r.Summary.Total != 0 {
		t.Fatalf("safe report expected zero findings, got %d: %+v", r.Summary.Total, r.Findings)
	}
	if len(r.Replacements) != 0 {
		t.Fatalf("safe report expected no replacements, got %+v", r.Replacements)
	}
	if r.Summary.ScannedPackages != 6 {
		t.Fatalf("expected 6 scanned packages, got %d", r.Summary.ScannedPackages)
	}
}

func ruleIDs(fs []Finding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return ids
}
