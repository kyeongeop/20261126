package main

import (
	"context"
	"testing"
)

func TestClassifierPrefixAndExact(t *testing.T) {
	c := NewClassifier(NamespacePolicy{
		Prefixes: []string{"@acme/", "go.acme.dev/"},
		Exact:    []string{"legacy-billing"},
	})

	cases := []struct {
		name     string
		internal bool
		prefix   string
	}{
		{"@acme/ui", true, "@acme/"},
		{"go.acme.dev/pkg/log", true, "go.acme.dev/"},
		{"legacy-billing", true, ""},
		{"lodash", false, ""},
		{"@other/scope", false, ""},
		{"acme-something", false, ""}, // prefix is not a fuzzy substring rule
	}
	for _, tc := range cases {
		m := c.Match(tc.name)
		if m.Internal != tc.internal {
			t.Errorf("Match(%q).Internal=%v want %v", tc.name, m.Internal, tc.internal)
		}
		if tc.internal && tc.prefix != "" && m.MatchedPrefix != tc.prefix {
			t.Errorf("Match(%q).MatchedPrefix=%q want %q", tc.name, m.MatchedPrefix, tc.prefix)
		}
		if tc.internal && tc.prefix == "" && m.MatchedExact == "" {
			t.Errorf("Match(%q) expected exact reservation", tc.name)
		}
	}
}

func TestNormalizeSHA256(t *testing.T) {
	hex := "8a679649f6fc387cfe8dd79a77c906f67e484cbf36a640f51b49753e22622d5a"
	want := "sha256:" + hex
	for _, in := range []string{hex, want, "sha256-" + hex} {
		got, ok := NormalizeSHA256(in)
		if !ok || got != want {
			t.Errorf("NormalizeSHA256(%q)=%q,%v want %q,true", in, got, ok, want)
		}
	}
	if _, ok := NormalizeSHA256("sha512-v2kDEe57leCulaDIuNTPy3Ry4g=="); ok {
		t.Error("sha512 SRI must not be treated as sha256")
	}
	if _, ok := NormalizeSHA256("not-a-digest"); ok {
		t.Error("garbage digest must be rejected")
	}
}

// TestOnlyUndeclaredHostFlagsExternalPackages proves arbitrary external OSS is
// not treated as risky merely for being external: packages resolved from the
// declared public registry produce zero findings.
func TestExternalPackagesNotFlagged(t *testing.T) {
	cfg := &Config{
		Project: "plain-oss",
		Registries: []Registry{
			{ID: "public", URL: "https://registry.npmjs.org", Kind: RegistryPublic, Default: true},
		},
		Namespace: NamespacePolicy{Prefixes: []string{"@acme/"}, Fallback: "deny"},
	}
	mf := &Manifest{Dependencies: []Dependency{
		{Name: "lodash", Spec: "4.17.21"},
		{Name: "express", Spec: "4.19.2"},
		{Name: "@babel/core", Spec: "7.24.0"},
		{Name: "left-pad", Spec: "1.3.0"},
	}}
	lf := &Lockfile{Entries: []LockEntry{
		{Name: "lodash", Version: "4.17.21", Resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
		{Name: "express", Version: "4.19.2", Resolved: "https://registry.npmjs.org/express/-/express-4.19.2.tgz"},
		{Name: "@babel/core", Version: "7.24.0", Resolved: "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"},
		{Name: "left-pad", Version: "1.3.0", Resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
	}}
	pub := &PublicCatalog{Packages: map[string]PublicPackage{
		"lodash": {Name: "lodash", Latest: "4.17.21"},
	}}

	r, err := NewChecker(cfg, mf, lf, pub, &InternalIndex{}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK || r.Summary.Total != 0 {
		t.Fatalf("ordinary external packages must be clean, got findings: %+v", r.Findings)
	}
}
