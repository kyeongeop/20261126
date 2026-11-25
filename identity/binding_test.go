package identity_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"certgateway/identity"
)

func TestBindingExtensionRoundTrip(t *testing.T) {
	want := identity.Binding{Service: "billing.internal", Purpose: identity.PurposeMetrics, InvitationID: "inv_123"}

	ext, err := want.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if ext.Critical {
		t.Fatal("binding extension must be non-critical to remain verifiable by crypto/x509")
	}

	uri, err := want.URI()
	if err != nil {
		t.Fatalf("URI: %v", err)
	}
	got, err := identity.ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if got != want {
		t.Fatalf("URI round trip = %+v, want %+v", got, want)
	}
}

func TestBindingValidation(t *testing.T) {
	cases := []identity.Binding{
		{Service: "", Purpose: identity.PurposeAPI, InvitationID: "i"},
		{Service: "svc", Purpose: "drop-tables", InvitationID: "i"},
		{Service: "svc", Purpose: identity.PurposeAPI, InvitationID: ""},
	}
	for i, b := range cases {
		if err := b.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error for %+v", i, b)
		}
		if _, err := b.Extension(); err == nil {
			t.Fatalf("case %d: Extension expected error", i)
		}
	}
}

func TestCheckRejectsMismatch(t *testing.T) {
	b := identity.Binding{Service: "orders.internal", Purpose: identity.PurposeAPI, InvitationID: "inv_1"}
	uri, err := b.URI()
	if err != nil {
		t.Fatal(err)
	}
	ext, err := b.Extension()
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{URIs: []*url.URL{uri}, Extensions: []pkix.Extension{ext}}

	if _, err := identity.Check(cert, "billing.internal", ""); err == nil {
		t.Fatal("expected service mismatch error")
	}
	if _, err := identity.Check(cert, "orders.internal", identity.PurposeAdmin); err == nil {
		t.Fatal("expected purpose mismatch error")
	}
	got, err := identity.Check(cert, "orders.internal", identity.PurposeAPI)
	if err != nil {
		t.Fatalf("expected match, got %v", err)
	}
	if got != b {
		t.Fatalf("Check returned %+v, want %+v", got, b)
	}
}

func TestFromCertificateRequiresBinding(t *testing.T) {
	if _, err := identity.FromCertificate(&x509.Certificate{}); err == nil {
		t.Fatal("expected ErrNoBinding for certificate without extension")
	}
}
