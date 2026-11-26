package main

import (
	"context"
	"strings"
	"testing"
)

func TestParseNpmrc(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		"# comment",
		"; other comment",
		"registry=https://registry.npmjs.org/",
		"@acme:registry=https://pkgs.acme.test",
		"//registry.npmjs.org/:_authToken=secret",
		"",
	}, "\n"))
	rc, err := ParseNpmrc(in)
	if err != nil {
		t.Fatal(err)
	}
	if rc.DefaultRegistry != "https://registry.npmjs.org/" {
		t.Errorf("default registry = %q", rc.DefaultRegistry)
	}
	if rc.Scoped["@acme"] != "https://pkgs.acme.test" {
		t.Errorf("scoped registry = %q", rc.Scoped["@acme"])
	}

	existing := []Registry{{ID: "acme-internal", URL: "https://pkgs.acme.test", Kind: RegistryInternal}}
	regs := rc.Registries(NamespacePolicy{InternalRegistryID: "acme-internal"}, existing)
	byURL := map[string]RegistryKind{}
	for _, r := range regs {
		byURL[r.URL] = r.Kind
	}
	if byURL["https://pkgs.acme.test"] != RegistryInternal {
		t.Errorf("scoped URL matching internal registry should be internal, got %q", byURL["https://pkgs.acme.test"])
	}
	if byURL["https://registry.npmjs.org/"] != RegistryPublic {
		t.Errorf("default registry should be public, got %q", byURL["https://registry.npmjs.org/"])
	}

	merged := mergeRegistries(existing, regs)
	if len(merged) != len(existing)+1 {
		t.Fatalf("equivalent internal URL must dedupe; merged=%d", len(merged))
	}
}

// A host declared only through .npmrc must count as declared, so an external
// package resolved through it is not DG101.
func TestNpmrcDeclaredHostSuppressesDG101(t *testing.T) {
	rc := &Npmrc{DefaultRegistry: "https://npm.corp.test"}
	cfg := &Config{
		Registries: rc.Registries(NamespacePolicy{}, nil),
		Namespace:  NamespacePolicy{Prefixes: []string{"@acme/"}, Fallback: "deny"},
	}
	mf := &Manifest{Dependencies: []Dependency{{Name: "lodash", Spec: "4.17.21"}}}
	lf := &Lockfile{Entries: []LockEntry{{
		Name:     "lodash",
		Version:  "4.17.21",
		Resolved: "https://npm.corp.test/lodash/-/lodash-4.17.21.tgz",
	}}}
	r, err := NewChecker(cfg, mf, lf, &PublicCatalog{Packages: map[string]PublicPackage{}}, &InternalIndex{}).
		Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Summary.Total != 0 {
		t.Fatalf("npmrc-declared host must be clean, got %+v", r.Findings)
	}
}
