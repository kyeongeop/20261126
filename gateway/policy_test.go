package gateway

import (
	"testing"
)

func TestResolvePriorityExactWildcardDefault(t *testing.T) {
	snapshot := testSnapshot(t, UnknownPolicyDefault, map[string]string{
		"shop.example.com": "exact",
		"*.example.com":    "wildcard",
	}, "default")

	tests := []struct {
		name        string
		sni         string
		kind        MatchKind
		pattern     string
		certificate string
	}{
		{name: "exact wins over wildcard", sni: "shop.example.com", kind: MatchExact, pattern: "shop.example.com", certificate: "exact"},
		{name: "exact is case insensitive", sni: "SHOP.Example.COM.", kind: MatchExact, pattern: "shop.example.com", certificate: "exact"},
		{name: "wildcard matches one label", sni: "api.example.com", kind: MatchWildcard, pattern: "*.example.com", certificate: "wildcard"},
		{name: "wildcard does not match apex", sni: "example.com", kind: MatchDefault, certificate: "default"},
		{name: "wildcard does not match multiple labels", sni: "a.b.example.com", kind: MatchDefault, certificate: "default"},
		{name: "unknown uses default", sni: "unlisted.example.org", kind: MatchDefault, certificate: "default"},
		{name: "missing SNI uses default", sni: "", kind: MatchDefault, certificate: "default"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection := snapshot.Resolve(test.sni)
			if selection.Kind != test.kind {
				t.Fatalf("kind = %q, want %q", selection.Kind, test.kind)
			}
			if selection.Pattern != test.pattern {
				t.Fatalf("pattern = %q, want %q", selection.Pattern, test.pattern)
			}
			if selection.CertificateName != test.certificate {
				t.Fatalf("certificate = %q, want %q", selection.CertificateName, test.certificate)
			}
			if !selection.Selected() {
				t.Fatal("expected a selected certificate")
			}
		})
	}
}

func TestResolveMostSpecificWildcard(t *testing.T) {
	snapshot := testSnapshot(t, UnknownPolicyReject, map[string]string{
		"*.example.com":     "wildcard",
		"*.api.example.com": "exact",
	}, "")

	selection := snapshot.Resolve("v1.api.example.com")
	if selection.Kind != MatchWildcard {
		t.Fatalf("kind = %q, want wildcard", selection.Kind)
	}
	if selection.Pattern != "*.api.example.com" {
		t.Fatalf("pattern = %q, want the most specific wildcard", selection.Pattern)
	}

	selection = snapshot.Resolve("v1.example.com")
	if selection.Pattern != "*.example.com" {
		t.Fatalf("pattern = %q, want generic wildcard", selection.Pattern)
	}
}

func TestResolveUnknownReject(t *testing.T) {
	snapshot := testSnapshot(t, UnknownPolicyReject, map[string]string{
		"*.example.com": "wildcard",
	}, "")

	for _, sni := range []string{"unknown.example.org", "example.com", ""} {
		selection := snapshot.Resolve(sni)
		if selection.Kind != MatchRejected {
			t.Fatalf("Resolve(%q) kind = %q, want rejected", sni, selection.Kind)
		}
		if selection.Selected() {
			t.Fatalf("Resolve(%q) unexpectedly selected a certificate", sni)
		}
	}
}
