package token

import "testing"

func TestActionsForPurpose(t *testing.T) {
	cases := map[Purpose][]Action{
		PurposeReadOnly: {ActionRead},
		PurposePublish:  {ActionPublish},
		PurposeRevoke:   {ActionRevoke},
	}
	for purpose, want := range cases {
		got, err := ActionsForPurpose(purpose)
		if err != nil {
			t.Fatalf("%s: %v", purpose, err)
		}
		if len(got) != len(want) || got[0] != want[0] {
			t.Fatalf("%s: got %v want %v", purpose, got, want)
		}
	}
	if _, err := ActionsForPurpose("admin"); err == nil {
		t.Fatal("expected error for unknown purpose")
	}
}

func TestScopeAllows(t *testing.T) {
	scope := Scope{
		Actions:         []Action{ActionRead},
		NamespacePrefix: "acme/",
		PackagePattern:  "acme/billing-*",
	}
	if err := scope.Validate(); err != nil {
		t.Fatal(err)
	}
	if !scope.Allows(ActionRead, "acme/", "billing-api") {
		t.Fatal("read on acme/billing-api should be allowed")
	}
	if scope.Allows(ActionPublish, "acme/", "billing-api") {
		t.Fatal("publish must not be allowed by a readonly scope")
	}
	if scope.Allows(ActionRead, "acme/", "auth-api") {
		t.Fatal("package outside the pattern must be denied")
	}
	if scope.Allows(ActionRead, "other/", "billing-api") {
		t.Fatal("namespace outside the prefix must be denied")
	}
	if scope.Allows(ActionRead, "acme", "billing-api") {
		t.Fatal("prefix must match on segment boundary (acme/ != acme)")
	}
}

func TestScopeValidate(t *testing.T) {
	if err := (Scope{Actions: []Action{ActionRead}}).Validate(); err == nil {
		t.Fatal("empty namespace prefix must be rejected: tokens are never global")
	}
	if err := (Scope{Actions: []Action{"delete"}, NamespacePrefix: "a/"}).Validate(); err == nil {
		t.Fatal("unknown action must be rejected")
	}
	if err := (Scope{NamespacePrefix: "a/"}).Validate(); err == nil {
		t.Fatal("empty action list must be rejected")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Actions: []Action{ActionRead}, NamespacePrefix: "acme/"}
	secret, rec, err := st.Create("ci-read", scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Lookup(secret); !ok {
		t.Fatal("fresh token should resolve")
	}
	if _, ok := st.Lookup("ireg_wrong"); ok {
		t.Fatal("unknown secret must not resolve")
	}
	// Reload from disk: only the hash was persisted.
	st2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := st2.Lookup(secret); !ok || got.ID != rec.ID {
		t.Fatal("token should survive reload")
	}
	if !st2.Revoke(rec.ID) {
		t.Fatal("revoke should succeed")
	}
	if _, ok := st2.Lookup(secret); ok {
		t.Fatal("revoked token must not resolve")
	}
}
